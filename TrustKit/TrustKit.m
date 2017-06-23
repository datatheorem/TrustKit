/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit.h"
#import "Reporting/TSKBackgroundReporter.h"
#import "Pinning/TSKSPKIHashCache.h"
#import "Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import "Swizzling/TSKNSURLSessionDelegateProxy.h"
#import "Pinning/TSKSPKIHashCache.h"
#import "parse_configuration.h"
#import "TSKPinningValidatorResult.h"
#import "TSKLog.h"

// Info.plist key we read the public key hashes from
static NSString * const kTSKConfiguration = @"TSKConfiguration";


#pragma mark TrustKit Global State

// Shared TrustKit singleton instance
static TrustKit *sharedTrustKit = nil;

// A shared hash cache for use by all TrustKit instances
static TSKSPKIHashCache *sharedHashCache;

static char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";

// Default report URI - can be disabled with TSKDisableDefaultReportUri
// Email info@datatheorem.com if you need a free dashboard to see your App's reports
static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";

#pragma mark TrustKit Initialization Helper Functions

@interface TrustKit ()
- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> *)trustKitConfig isSingleton:(BOOL)isSingleton;
@property (nonatomic) TSKBackgroundReporter *pinFailureReporter;
@property (nonatomic) dispatch_queue_t pinFailureReporterQueue;
@end

@implementation TrustKit

#pragma mark Shared TrustKit Explicit Initialization

+ (instancetype)sharedInstance
{
    if (!sharedTrustKit) {
        // TrustKit should only be initialized once so we don't double swizzle or get into anything unexpected
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
        sharedTrustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig isSingleton:YES];
        
        // Hook network APIs if needed
        if ([sharedTrustKit.configuration[kTSKSwizzleNetworkDelegates] boolValue]) {
            // NSURLConnection
            [TSKNSURLConnectionDelegateProxy swizzleNSURLConnectionConstructors:sharedTrustKit];
            
            // NSURLSession
            [TSKNSURLSessionDelegateProxy swizzleNSURLSessionConstructors:sharedTrustKit];
        }
    });
}


#pragma mark Instance


- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> *)trustKitConfig
{
    return [self initWithConfiguration:trustKitConfig isSingleton:NO];
}


- (instancetype)initWithConfiguration:(NSDictionary<NSString *, id> *)trustKitConfig isSingleton:(BOOL)isSingleton
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
        
        // Handle global configuration flags here
        // TSKIgnorePinningForUserDefinedTrustAnchors
#if TARGET_OS_IPHONE
        BOOL userTrustAnchorBypass = NO;
#else
        BOOL userTrustAnchorBypass = [_configuration[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue];
#endif
        
        // TSKSwizzleNetworkDelegates - check if we are initializing the singleton / shared instance
        if (!isSingleton)
        {
            if ([_configuration[kTSKSwizzleNetworkDelegates] boolValue] == YES)
            {
                // TSKSwizzleNetworkDelegates can only be enabled when using the shared instance, to avoid double swizzling
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"Cannot use TSKSwizzleNetworkDelegates outside the TrustKit sharedInstance"];
            }
            
            if ((sharedTrustKit) && ([[sharedTrustKit configuration][kTSKSwizzleNetworkDelegates] boolValue] == YES))
            {
                // Local instances cannot be used if a shared instance with swizzling enabled is used, to avoid double pinning validation
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"Cannot use local TrustKit instances when the TrustKit sharedInstance has been initialized with kTSKSwizzleNetworkDelegates enabled"];
            }
        }
        
        // Configure the pinning validator and register for pinning callbacks in order to
        // trigger reports on the pinning failure reporter background queue.
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            sharedHashCache = [[TSKSPKIHashCache alloc] initWithIdentifier:kTSKSPKISharedHashCacheIdentifier];
        });
        
        __weak typeof(self) weakSelf = self;
        _pinningValidator = [[TSKPinningValidator alloc] initWithPinnedDomainConfig:_configuration
                                                                          hashCache:sharedHashCache
                                                      ignorePinsForUserTrustAnchors:userTrustAnchorBypass
                                                              validationResultQueue:_pinFailureReporterQueue
                                                            validationResultHandler:^(TSKPinningValidatorResult * _Nonnull result) {
                                                                typeof(self) strongSelf = weakSelf;
                                                                if (!strongSelf) {
                                                                    return;
                                                                }
                                                                
                                                                // Invoke client handler if set
                                                                void(^callback)(TSKPinningValidatorResult *) = strongSelf.validationDelegateCallback;
                                                                if (callback) {
                                                                    dispatch_async(self.validationDelegateQueue, ^{
                                                                        callback(result);
                                                                    });
                                                                }
                                                                
                                                                // Send analytics report
                                                                [strongSelf sendValidationReport:result];
                                                            }];
        
        TSKLog(@"Successfully initialized with configuration %@", _configuration);
    }
    return self;
}


#pragma mark Notification Handlers

// The block which receives pin validation results and turns them into pin validation reports
- (void)sendValidationReport:(TSKPinningValidatorResult *)result
{
    TSKTrustEvaluationResult validationResult = result.validationResult;
    
    // Send a report only if the there was a pinning failure
    if (validationResult != TSKTrustEvaluationSuccess)
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

@end


#pragma mark TrustKit Implicit Initialization via Library Constructor


__attribute__((constructor)) static void initializeWithInfoPlist(int argc, const char **argv)
{
    // TrustKit just got started in the App
    CFBundleRef appBundle = CFBundleGetMainBundle();
    
    // Retrieve the configuration from the App's Info.plist file
    NSDictionary *trustKitConfigFromInfoPlist = (__bridge NSDictionary *)CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)kTSKConfiguration);
    if (trustKitConfigFromInfoPlist)
    {
        TSKLog(@"Configuration supplied via the App's Info.plist");
        [TrustKit initializeWithConfiguration:trustKitConfigFromInfoPlist];
    }
}
