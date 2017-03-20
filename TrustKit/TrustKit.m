/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"
#import "Reporting/TSKBackgroundReporter.h"
#import "Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import "Swizzling/TSKNSURLSessionDelegateProxy.h"
#import "parse_configuration.h"
#import "TSKPinningValidatorResult.h"


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

#pragma mark TrustKit Global State
// Shared TrustKit singleton instance
static TrustKit *sharedTrustKit = nil;

static char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";

// Default report URI - can be disabled with TSKDisableDefaultReportUri
// Email info@datatheorem.com if you need a free dashboard to see your App's reports
static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";

#pragma mark TrustKit Initialization Helper Functions

@interface TrustKit ()
@property (nonatomic) TSKBackgroundReporter *pinFailureReporter;
@property (nonatomic) dispatch_queue_t pinFailureReporterQueue;
@end

@implementation TrustKit

#pragma mark Shared TrustKit Explicit Initialization

+ (instancetype)sharedInstance
{
    if (!sharedTrustKit) {
        // TrustKit should only be initialized once so we don't double interpose SecureTransport or get into anything unexpected
        [NSException raise:@"TrustKit was not initialized"
                    format:@"TrustKit must be initialized using +initializeWithConfiguration: prior to accessing sharedInstance"];
    }
    return sharedTrustKit;
}

+ (void)initializeWithConfiguration:(NSDictionary *)trustKitConfig
{
    TSKLog(@"Configuration passed via explicit call to initializeWithConfiguration:");
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedTrustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
        
        // Hook network APIs if needed
        if ([sharedTrustKit.configuration[kTSKSwizzleNetworkDelegates] boolValue]) {
            // NSURLConnection
            [TSKNSURLConnectionDelegateProxy swizzleNSURLConnectionConstructors];
            
            // NSURLSession
            [TSKNSURLSessionDelegateProxy swizzleNSURLSessionConstructors];
        }
    });
}

+ (void)setLoggerBlock:(void (^)(NSString *))block
{
    TrustKit *singleton = [self sharedInstance];
}

+ (NSDictionary * _Nullable)configuration
{
    TrustKit *singleton = [self sharedInstance];
    return singleton.configuration;
}

#pragma mark Instance

- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> *)trustKitConfig
{
    NSParameterAssert(trustKitConfig);
    if (!trustKitConfig) {
        return nil;
    }
    
    self = [super init];
    if (self && [trustKitConfig count] > 0) {
        // Convert and store the SSL pins in our global variable
        _configuration = parseTrustKitConfiguration(trustKitConfig);
        
        _validationDelegateQueue = dispatch_get_main_queue();
        
        // Create a dispatch queue for activating the reporter
        // We use a serial queue targetting the global default queue in order to ensure reports are sent one by one
        // even when a lot of pin failures are occuring, instead of spamming the global queue with events to process
        _pinFailureReporterQueue = dispatch_queue_create(kTSKPinFailureReporterQueueLabel, DISPATCH_QUEUE_SERIAL);
        
        // Create our reporter for sending pin validation failures; do this before hooking NSURLSession so we don't hook ourselves
        _pinFailureReporter = [[TSKBackgroundReporter alloc] initAndRateLimitReports:YES];
        
        // Configure the pinning validator and register for pinning callbacks in order to
        // trigger reports on the pinning failure reporter background queue.
#if TARGET_OS_IPHONE
        BOOL userTrustAnchorBypass = NO;
#else
        BOOL userTrustAnchorBypass = [_configuration[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue];
#endif
        __weak typeof(self) weakSelf = self;
        _pinningValidator = [[TSKPinningValidator alloc] initWithPinnedDomainConfig:_configuration[kTSKPinnedDomains]
                                                      ignorePinsForUserTrustAnchors:userTrustAnchorBypass
                                                              validationResultQueue:_pinFailureReporterQueue
                                                            validationResultHandler:^(TSKPinningValidatorResult * _Nonnull result) {
                                                            
                                                                // Invoke client handler if set
                                                                void(^callback)(TSKPinningValidatorResult *) = self.validationDelegateCallback;
                                                                if (callback) {
                                                                    dispatch_async(self.validationDelegateQueue, ^{
                                                                        callback(result);
                                                                    });
                                                                }
                                                                
                                                                // Send analytics report
                                                                [weakSelf sendValidationReport:result];
                                                            }];
        
        TSKLog(@"Successfully initialized with configuration %@", _configuration);
    }
    return self;
}

#pragma mark Notification Handlers

// The block which receives pin validation notification and turns them into pin validation reports
- (void)sendValidationReport:(TSKPinningValidatorResult *)result
{
    TSKPinValidationResult validationResult = result.validationResult;
    
    // Send a report only if the there was a pinning failure
    if (validationResult != TSKPinValidationResultSuccess)
    {
#if !TARGET_OS_IPHONE
        if (validationResult != TSKPinValidationResultFailedUserDefinedTrustAnchor)
#endif
        {
            NSString *notedHostname = result.notedHostname;
            NSDictionary *notedHostnameConfig = self.configuration[kTSKPinnedDomains][notedHostname];
            
            // Pin validation failed: retrieve the list of configured report URLs
            NSMutableArray *reportUris = [NSMutableArray arrayWithArray:notedHostnameConfig[kTSKReportUris]];
            
            // Also enable the default reporting URL
            if ([notedHostnameConfig[kTSKDisableDefaultReportUri] boolValue] == NO)
            {
                [reportUris addObject:[NSURL URLWithString:kTSKDefaultReportUri]];
            }
            
            // If some report URLs have been defined, send the pin failure report
            if (reportUris.count > 0)
            {
                [self.pinFailureReporter pinValidationFailedForHostname:result.serverHostname
                                                                   port:nil
                                                       certificateChain:result.certificateChain
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
}

- (void)setValidationDelegateQueue:(dispatch_queue_t)validationDelegateQueue
{
    _validationDelegateQueue = validationDelegateQueue ?: dispatch_get_main_queue();
}

# pragma mark Private / Test Methods

+ (void)resetConfiguration
{
    //sharedTrustKitOnceToken = 0;
    // Reset is only available/used for tests
    //resetSubjectPublicKeyInfoCache();
    //_spkiHashCache = [TSKSPKIHashCache new];
    //_configuration = nil;
//    _isTrustKitInitialized = NO;
}

+ (NSString *)getDefaultReportUri
{
    return kTSKDefaultReportUri;
}

+ (TSKBackgroundReporter *)getGlobalPinFailureReporter
{
    TrustKit *singleton = [self sharedInstance];
    return singleton.pinFailureReporter;
}

+ (void)setGlobalPinFailureReporter:(TSKBackgroundReporter *) reporter
{
    TrustKit *singleton = [self sharedInstance];
    singleton.pinFailureReporter = reporter;
}

@end


#pragma mark TrustKit Implicit Initialization via Library Constructor

// TRUSTKIT_SKIP_LIB_INITIALIZATION define allows consumers to opt out of the dylib constructor.
// This might be useful to mitigate integration risks, if the consumer doens't wish to use
// plist file, and wants to initialize lib manually later on.
//#ifndef TRUSTKIT_SKIP_LIB_INITIALIZATION
//
//__attribute__((constructor)) static void initializeWithInfoPlist(int argc, const char **argv)
//{
//    // TrustKit just got started in the App
//    CFBundleRef appBundle = CFBundleGetMainBundle();
//    
//    // Retrieve the configuration from the App's Info.plist file
//    NSDictionary *trustKitConfigFromInfoPlist = (__bridge NSDictionary *)CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)kTSKConfiguration);
//    if (trustKitConfigFromInfoPlist)
//    {
//        TSKLog(@"Configuration supplied via the App's Info.plist");
//        initializeTrustKit(trustKitConfigFromInfoPlist);
//    }
//}
//
//#endif
