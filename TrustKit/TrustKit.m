/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"
#import "Pinning/public_key_utils.h"
#import "Reporting/TSKBackgroundReporter.h"
#import "Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import "Swizzling/TSKNSURLSessionDelegateProxy.h"
#import "parse_configuration.h"
#import "Reporting/reporting_utils.h"


NSString * const TrustKitVersion = @"1.4.2";

#pragma mark Configuration Constants

// Info.plist key we read the public key hashes from
static const NSString *kTSKConfiguration = @"TSKConfiguration";

// General keys
const TSKGlobalConfigurationKey kTSKSwizzleNetworkDelegates = @"TSKSwizzleNetworkDelegates";
const TSKGlobalConfigurationKey kTSKPinnedDomains = @"TSKPinnedDomains";

const TSKGlobalConfigurationKey kTSKIgnorePinningForUserDefinedTrustAnchors = @"TSKIgnorePinningForUserDefinedTrustAnchors";

// Keys for each domain within the TSKPinnedDomains entry
const TSKDomainConfigurationKey kTSKPublicKeyHashes = @"TSKPublicKeyHashes";
const TSKDomainConfigurationKey kTSKEnforcePinning = @"TSKEnforcePinning";
const TSKDomainConfigurationKey kTSKExcludeSubdomainFromParentPolicy = @"kSKExcludeSubdomainFromParentPolicy";

const TSKDomainConfigurationKey kTSKIncludeSubdomains = @"TSKIncludeSubdomains";
const TSKDomainConfigurationKey kTSKPublicKeyAlgorithms = @"TSKPublicKeyAlgorithms";
const TSKDomainConfigurationKey kTSKReportUris = @"TSKReportUris";
const TSKDomainConfigurationKey kTSKDisableDefaultReportUri = @"TSKDisableDefaultReportUri";
const TSKDomainConfigurationKey kTSKExpirationDate = @"TSKExpirationDate";

#pragma mark Public key Algorithms Constants
const TSKSupportedAlgorithm kTSKAlgorithmRsa2048 = @"TSKAlgorithmRsa2048";
const TSKSupportedAlgorithm kTSKAlgorithmRsa4096 = @"TSKAlgorithmRsa4096";
const TSKSupportedAlgorithm kTSKAlgorithmEcDsaSecp256r1 = @"TSKAlgorithmEcDsaSecp256r1";
const TSKSupportedAlgorithm kTSKAlgorithmEcDsaSecp384r1 = @"TSKAlgorithmEcDsaSecp384r1";

#pragma mark Notification keys
NSString *kTSKValidationCompletedNotification   = @"TSKValidationCompletedNotification";

const TSKNotificationUserInfoKey kTSKValidationDurationNotificationKey = @"TSKValidationDurationNotificationKey";
const TSKNotificationUserInfoKey kTSKValidationResultNotificationKey   = @"TSKValidationResultNotificationKey";
const TSKNotificationUserInfoKey kTSKValidationDecisionNotificationKey = @"TSKValidationDecisionNotificationKey";
const TSKNotificationUserInfoKey kTSKValidationCertificateChainNotificationKey = @"TSKValidationCertificateChainNotificationKey";
const TSKNotificationUserInfoKey kTSKValidationNotedHostnameNotificationKey = @"TSKValidationNotedHostnameNotificationKey";
const TSKNotificationUserInfoKey kTSKValidationServerHostnameNotificationKey = @"TSKValidationServerHostnameNotificationKey";


#pragma mark TrustKit Global State
// Global dictionary for storing the public key hashes and domains
static NSDictionary *_trustKitGlobalConfiguration = nil;

// Global preventing multiple initializations (double method swizzling, etc.)
static BOOL _isTrustKitInitialized = NO;
static dispatch_once_t dispatchOnceTrustKitInit;

// Reporter for sending pin violation reports
static TSKBackgroundReporter *_pinFailureReporter = nil;
static char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";
static dispatch_queue_t _pinFailureReporterQueue = NULL;
static id _pinValidationObserver = nil;


// Default report URI - can be disabled with TSKDisableDefaultReportUri
// Email info@datatheorem.com if you need a free dashboard to see your App's reports
static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";


#pragma mark Default Logging Block

// Default logger block: only log in debug builds and add TrustKit at the beginning of the line
void (^_loggerBlock)(NSString *) = ^void(NSString *message)
{
#if DEBUG
    NSLog(@"=== TrustKit: %@", message);
#endif
};


// The logging function we use within TrustKit
void TSKLog(NSString *format, ...)
{
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat: format arguments:args];
    va_end(args);
    _loggerBlock(message);
}


#pragma mark Helper Function to Send Notifications and Reports

// Send a notification and release the serverTrust
void sendValidationNotification_async(NSString *serverHostname, SecTrustRef serverTrust, NSString *notedHostname, TSKPinValidationResult validationResult, TSKTrustDecision finalTrustDecision, NSTimeInterval validationDuration)
{
    // Convert the server trust to a certificate chain
    // This cannot be done in the dispatch_async() block as sometimes the serverTrust seems to become invalid once the block gets scheduled, even tho its retain count is still positive
    CFRetain(serverTrust);
    NSArray *certificateChain = convertTrustToPemArray(serverTrust);
    CFRelease(serverTrust);
    
    // Send the notification to consumers that want to get notified about all validations performed
    // We use the _pinFailureReporterQueue so our receving block sendReportFromNotificationBlock gets executed on this queue as well
    dispatch_async(_pinFailureReporterQueue, ^(void)
                   {
                       [[NSNotificationCenter defaultCenter] postNotificationName:kTSKValidationCompletedNotification
                                                                           object:nil
                                                                         userInfo:@{kTSKValidationDurationNotificationKey: @(validationDuration),
                                                                                    kTSKValidationDecisionNotificationKey: @(finalTrustDecision),
                                                                                    kTSKValidationResultNotificationKey: @(validationResult),
                                                                                    kTSKValidationCertificateChainNotificationKey: certificateChain,
                                                                                    kTSKValidationNotedHostnameNotificationKey: notedHostname,
                                                                                    kTSKValidationServerHostnameNotificationKey: serverHostname}];
                   });
}


// The block which receives pin validation notification and turns them into pin validation reports
static void (^sendReportFromNotificationBlock)(NSNotification *note) = ^void(NSNotification *note)
{
    NSDictionary *userInfo = [note userInfo];
    TSKPinValidationResult validationResult = [userInfo[kTSKValidationResultNotificationKey] integerValue];
    
    // Send a report only if the there was a pinning failure
    if (validationResult != TSKPinValidationResultSuccess)
    {
#if !TARGET_OS_IPHONE
        if (validationResult != TSKPinValidationResultFailedUserDefinedTrustAnchor)
#endif
        {
            NSString *notedHostname = userInfo[kTSKValidationNotedHostnameNotificationKey];
            NSDictionary *notedHostnameConfig = _trustKitGlobalConfiguration[kTSKPinnedDomains][notedHostname];
            
            // Pin validation failed: retrieve the list of configured report URLs
            NSMutableArray *reportUris = [NSMutableArray arrayWithArray:notedHostnameConfig[kTSKReportUris]];
            
            // Also enable the default reporting URL
            if ([notedHostnameConfig[kTSKDisableDefaultReportUri] boolValue] == NO)
            {
                [reportUris addObject:[NSURL URLWithString:kTSKDefaultReportUri]];
            }
            
            // If some report URLs have been defined, send the pin failure report
            if ((reportUris != nil) && ([reportUris count] > 0))
            {
                [_pinFailureReporter pinValidationFailedForHostname:userInfo[kTSKValidationServerHostnameNotificationKey]
                                                               port:nil
                                                   certificateChain:userInfo[kTSKValidationCertificateChainNotificationKey]
                                                      notedHostname:notedHostname
                                                         reportURIs:reportUris
                                                  includeSubdomains:[notedHostnameConfig[kTSKIncludeSubdomains] boolValue]
                                                     enforcePinning:[notedHostnameConfig[kTSKEnforcePinning] boolValue]
                                                          knownPins:notedHostnameConfig[kTSKPublicKeyHashes]
                                                   validationResult:validationResult
                                                     expirationDate:notedHostnameConfig[kTSKExpirationDate]];
            }
        }
    }
};


#pragma mark TrustKit Initialization Helper Functions

static void initializeTrustKit(NSDictionary *trustKitConfig)
{
    if (trustKitConfig == nil)
    {
        return;
    }
    
    if (_isTrustKitInitialized == YES)
    {
        // TrustKit should only be initialized once so we don't double interpose SecureTransport or get into anything unexpected
        [NSException raise:@"TrustKit already initialized"
                    format:@"TrustKit was already initialized with the following SSL pins: %@", _trustKitGlobalConfiguration];
    }
    
    if ([trustKitConfig count] > 0)
    {
        initializeSubjectPublicKeyInfoCache();
        
        // Convert and store the SSL pins in our global variable
        _trustKitGlobalConfiguration = [[NSDictionary alloc]initWithDictionary:parseTrustKitConfiguration(trustKitConfig)];
        
        
        // We use dispatch_once() here only so that unit tests don't reset the reporter
        // or the swizzling logic when calling [TrustKit resetConfiguration]
        dispatch_once(&dispatchOnceTrustKitInit, ^{
            // Create our reporter for sending pin validation failures; do this before hooking NSURLSession so we don't hook ourselves
            _pinFailureReporter = [[TSKBackgroundReporter alloc]initAndRateLimitReports:YES];
            
            
            // Create a dispatch queue for activating the reporter
            // We use a serial queue targetting the global default queue in order to ensure reports are sent one by one
            // even when a lot of pin failures are occuring, instead of spamming the global queue with events to process
            _pinFailureReporterQueue = dispatch_queue_create(kTSKPinFailureReporterQueueLabel, DISPATCH_QUEUE_SERIAL);
            dispatch_set_target_queue(_pinFailureReporterQueue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
            
            
            // Register for pinning notifications in order to trigger reports
            // Nil queue to run the block on the _pinFailureReporterQueue (where the notification is posted from)
            _pinValidationObserver = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                              object:nil
                                                                               queue:nil
                                                                          usingBlock:sendReportFromNotificationBlock];
            
            // Hook network APIs if needed
            if ([_trustKitGlobalConfiguration[kTSKSwizzleNetworkDelegates] boolValue] == YES)
            {
                // NSURLConnection
                [TSKNSURLConnectionDelegateProxy swizzleNSURLConnectionConstructors];
                
                // NSURLSession
                [TSKNSURLSessionDelegateProxy swizzleNSURLSessionConstructors];
            }
        });
        
        // All done
        _isTrustKitInitialized = YES;
        TSKLog(@"Successfully initialized with configuration %@", _trustKitGlobalConfiguration);
    }
}


@implementation TrustKit


#pragma mark TrustKit Explicit Initialization

+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig
{
    TSKLog(@"Configuration passed via explicit call to initializeWithConfiguration:");
    initializeTrustKit(trustKitConfig);
}

+ (void)setLoggerBlock:(void (^)(NSString *))block
{
    _loggerBlock = block;
}


# pragma mark Private / Test Methods

+ (NSDictionary *) configuration
{
    return [_trustKitGlobalConfiguration copy];
}


+ (BOOL) wasTrustKitInitialized
{
    return _isTrustKitInitialized;
}


+ (void) resetConfiguration
{
    // Reset is only available/used for tests
    resetSubjectPublicKeyInfoCache();
    _trustKitGlobalConfiguration = nil;
    _isTrustKitInitialized = NO;
}


+ (NSString *) getDefaultReportUri
{
    return kTSKDefaultReportUri;
}


+ (TSKBackgroundReporter *) getGlobalPinFailureReporter
{
    return _pinFailureReporter;
}


+ (void) setGlobalPinFailureReporter:(TSKBackgroundReporter *) reporter
{
    _pinFailureReporter = reporter;
}

@end


#pragma mark TrustKit Implicit Initialization via Library Constructor

// TRUSTKIT_SKIP_LIB_INITIALIZATION define allows consumers to opt out of the dylib constructor.
// This might be useful to mitigate integration risks, if the consumer doens't wish to use
// plist file, and wants to initialize lib manually later on.
#ifndef TRUSTKIT_SKIP_LIB_INITIALIZATION

__attribute__((constructor)) static void initializeWithInfoPlist(int argc, const char **argv)
{
    // TrustKit just got started in the App
    CFBundleRef appBundle = CFBundleGetMainBundle();
    
    // Retrieve the configuration from the App's Info.plist file
    NSDictionary *trustKitConfigFromInfoPlist = (__bridge NSDictionary *)CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)kTSKConfiguration);
    if (trustKitConfigFromInfoPlist)
    {
        TSKLog(@"Configuration supplied via the App's Info.plist");
        initializeTrustKit(trustKitConfigFromInfoPlist);
    }
}

#endif
