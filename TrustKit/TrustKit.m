/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"
#import "public_key_utils.h"
#import "TSKBackgroundReporter.h"
#import "TSKNSURLConnectionDelegateProxy.h"
#import "TSKNSURLSessionDelegateProxy.h"
#import "parse_configuration.h"


#pragma mark Configuration Constants

// Info.plist key we read the public key hashes from
static const NSString *kTSKConfiguration = @"TSKConfiguration";

// General keys
NSString * const kTSKSwizzleNetworkDelegates = @"TSKSwizzleNetworkDelegates";
NSString * const kTSKPinnedDomains = @"TSKPinnedDomains";
NSString * const kTSKPostValidationNotifications = @"TSKPostValidationNotifications";

// Keys for each domain within the TSKPinnedDomains entry
NSString * const kTSKPublicKeyHashes = @"TSKPublicKeyHashes";
NSString * const kTSKEnforcePinning = @"TSKEnforcePinning";
NSString * const kTSKIncludeSubdomains = @"TSKIncludeSubdomains";
NSString * const kTSKPublicKeyAlgorithms = @"TSKPublicKeyAlgorithms";
NSString * const kTSKReportUris = @"TSKReportUris";
NSString * const kTSKDisableDefaultReportUri = @"TSKDisableDefaultReportUri";
NSString * const kTSKIgnorePinningForUserDefinedTrustAnchors = @"TSKIgnorePinningForUserDefinedTrustAnchors";

#pragma mark Public key Algorithms Constants
NSString * const kTSKAlgorithmRsa2048 = @"TSKAlgorithmRsa2048";
NSString * const kTSKAlgorithmRsa4096 = @"TSKAlgorithmRsa4096";
NSString * const kTSKAlgorithmEcDsaSecp256r1 = @"TSKAlgorithmEcDsaSecp256r1";

#pragma mark Notification keys
NSString * const kTSKValidationCompletedNotification   = @"TSKValidationCompletedNotification";
NSString * const kTSKValidationDurationNotificationKey = @"TSKValidationDurationNotificationKey";
NSString * const kTSKValidationResultNotificationKey   = @"TSKValidationResultNotificationKey";
NSString * const kTSKValidationDecisionNotificationKey = @"TSKValidationDecisionNotificationKey";

#pragma mark TrustKit Global State
// Global dictionary for storing the public key hashes and domains
static NSDictionary *_trustKitGlobalConfiguration = nil;

// Global preventing multiple initializations (double function interposition, etc.)
static BOOL _isTrustKitInitialized = NO;
static dispatch_once_t dispatchOnceTrustKitInit;

// Reporter delegate for sending pin violation reports
static TSKBackgroundReporter *_pinFailureReporter = nil;
static char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";
static dispatch_queue_t _pinFailureReporterQueue = NULL;


// Default report URI - can be disabled with TSKDisableDefaultReportUri
// Email info@datatheorem.com if you need a free dashboard to see your App's reports
static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";


#pragma mark Logging Function

void TSKLog(NSString *format, ...)
{
    // Only log in debug builds
#if DEBUG
    NSString *newFormat = [[NSString alloc] initWithFormat:@"=== TrustKit: %@", format];
    va_list args;
    va_start(args, format);
    NSLogv(newFormat, args);
    va_end(args);
#endif
}


#pragma mark Helper Function to Send Reports


// Send a report if needed and release the serverTrust
void sendPinFailureReport_async(TSKPinValidationResult validationResult, SecTrustRef serverTrust, NSString *serverHostname, NSString *notedHostname, NSDictionary *notedHostnameConfig, void (^onCompletion)(void))
{
    dispatch_async(_pinFailureReporterQueue, ^(void) {
        
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
            [_pinFailureReporter pinValidationFailedForHostname:serverHostname
                                                           port:nil
                                                          trust:serverTrust
                                                  notedHostname:notedHostname
                                                     reportURIs:reportUris
                                              includeSubdomains:[notedHostnameConfig[kTSKIncludeSubdomains] boolValue]
                                                      knownPins:notedHostnameConfig[kTSKPublicKeyHashes]
                                               validationResult:validationResult];
        }
        
        if (onCompletion)
        {
            // We usually use this to CFRelease() the serverTrust
            onCompletion();
        }
    });
}



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
        _trustKitGlobalConfiguration = [[NSDictionary alloc]initWithDictionary:parseConfiguration(trustKitConfig)];
        
        
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


# pragma mark Private / Test Methods

+ (NSDictionary *) configuration
{
    return _trustKitGlobalConfiguration;
}


+ (BOOL) wasTrustKitInitialized
{
    return _isTrustKitInitialized;
}


+ (void) resetConfiguration
{
    // This is only used for tests
    resetSubjectPublicKeyInfoCache();
    _trustKitGlobalConfiguration = nil;
    _isTrustKitInitialized = NO;
}


+ (NSString *) getDefaultReportUri
{
    return kTSKDefaultReportUri;
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
