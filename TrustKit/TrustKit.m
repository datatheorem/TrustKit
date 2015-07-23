/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"
#include <dlfcn.h>
#import <CommonCrypto/CommonDigest.h>
#import "fishhook.h"
#import "public_key_utils.h"
#import "domain_registry.h"
#import "TSKBackgroundReporter.h"
#import "TSKSimpleReporter.h"


#pragma mark Configuration Constants

// Info.plist key we read the public key hashes from
static NSString * const kTSKConfiguration = @"TSKConfiguration";


// Keys for each domain within the config dictionnary
const NSString *kTSKPublicKeyHashes = @"TSKPublicKeyHashes";
const NSString *kTSKEnforcePinning = @"TSKEnforcePinning";
const NSString *kTSKIncludeSubdomains = @"TSKIncludeSubdomains";
const NSString *kTSKPublicKeyAlgorithms = @"TSKPublicKeyAlgorithms";
const NSString *kTSKReportUris = @"TSKReportUris";
const NSString *kTSKDisableDefaultReportUri = @"TSKDisableDefaultReportUri";
const NSString *kTSKIgnorePinningForUserDefinedTrustAnchors = @"TSKIgnorePinningForUserDefinedTrustAnchors";

#pragma mark Public key Algorithms Constants
const NSString *kTSKAlgorithmRsa2048 = @"TSKAlgorithmRsa2048";
const NSString *kTSKAlgorithmRsa4096 = @"TSKAlgorithmRsa4096";
const NSString *kTSKAlgorithmEcDsaSecp256r1 = @"TSKAlgorithmEcDsaSecp256r1";


#pragma mark TrustKit Global State
// Global dictionnary for storing the public key hashes and domains
static NSDictionary *_trustKitGlobalConfiguration = nil;

// Global preventing multiple initializations (double function interposition, etc.)
static BOOL _isTrustKitInitialized = NO;
static dispatch_once_t dispatchOnceTrustKitInit;

// Reporter delegate for sending pin violation reports
static id _pinFailureReporter = nil;
static char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";
static dispatch_queue_t _pinFailureReporterQueue = NULL;

// For tests
static BOOL _wasTrustKitCalled = NO;


// Default report URI - can be disabled with TSKDisableDefaultReportUri
static NSString * const kTSKDefaultReportUri = @"https://trustkit-reports-server.appspot.com/log_report";


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
        
#if !DEBUG
        // For release builds, also enable the default reporting URL
        if ([notedHostnameConfig[kTSKDisableDefaultReportUri] boolValue] == NO)
        {
            [reportUris addObject:[NSURL URLWithString:kTSKDefaultReportUri]];
        }
#endif
        
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


#pragma mark SSLHandshake Hook


static OSStatus (*original_SSLHandshake)(SSLContextRef context) = NULL;

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{
    OSStatus result = original_SSLHandshake(context);
    if ((result == noErr) && (_isTrustKitInitialized))
    {
        // The handshake was sucessful, let's do our additional checks on the server certificate
        _wasTrustKitCalled = YES;
        char *serverName = NULL;
        size_t serverNameLen = 0;
        
        // Get the server's domain name
        SSLGetPeerDomainNameLength (context, &serverNameLen);
        serverName = malloc(serverNameLen+1);
        SSLGetPeerDomainName(context, serverName, &serverNameLen);
        serverName[serverNameLen] = '\0';
        NSString *serverNameStr = [NSString stringWithUTF8String:serverName];
        free(serverName);
        
        // Retrieve the pinning configuration for this specific domain, if there is one
        NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverNameStr, _trustKitGlobalConfiguration);
        if (domainConfigKey != nil)
        {
            // This domain is pinned
            NSDictionary *domainConfig = _trustKitGlobalConfiguration[domainConfigKey];
            
            // Retrieve the server's trust object
            SecTrustRef serverTrust;
            SSLCopyPeerTrust(context, &serverTrust);
            
            // Re-evaluate the server's certificate chain and look for one the configured SPKI pins
            TSKPinValidationResult validationResult = TSKPinValidationResultFailed;
            validationResult = verifyPublicKeyPin(serverTrust, serverNameStr, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
            
            if (validationResult == TSKPinValidationResultSuccess)
            {
                // Pin validation was successful
                CFRelease(serverTrust);
            }
            else
            {
                // Pin validation failed
#if !TARGET_OS_IPHONE
                if ((validationResult == TSKPinValidationResultFailedUserDefinedTrustAnchor)
                    && ([domainConfig[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue] == YES))
                {
                    // OS-X only: user-defined trust anchors can be whitelisted (for corporate proxies, etc.)
                    TSKLog(@"Ignoring pinning result for user-defined trust anchor");
                    CFRelease(serverTrust);
                }
                else
#endif
                {
                    // Send a pin failure report
                    sendPinFailureReport_async(validationResult, serverTrust, serverNameStr, domainConfigKey, domainConfig, ^void (void)
                                               {
                                                   // Release the trust once the report has been sent
                                                   CFRelease(serverTrust);
                                               });
                    
                    // If TrustKit was configured to enforce pinning, make the connection fail
                    if ([domainConfig[kTSKEnforcePinning] boolValue] == YES)
                    {
                        result = errSSLXCertChainInvalid;
                    }
                }
            }
        }
    }
    return result;
}


#pragma mark TrustKit Initialization Helper Functions


NSDictionary *parseTrustKitArguments(NSDictionary *TrustKitArguments)
{
    // Convert settings supplied by the user to a configuration dictionnary that can be used by TrustKit
    // This includes checking the sanity of the settings and converting public key hashes/pins from an
    // NSSArray of NSStrings (as provided by the user) to an NSSet of NSData (as needed by TrustKit)
    
    // Initialize domain registry library
    InitializeDomainRegistry();
    
    NSMutableDictionary *finalConfiguration = [[NSMutableDictionary alloc]init];
    
    for (NSString *domainName in TrustKitArguments)
    {
        // Sanity checks on the domain name
        if (GetRegistryLength([domainName UTF8String]) == 0)
        {
            [NSException raise:@"TrustKit configuration invalid"
                        format:@"TrustKit was initialized with an invalid domain %@", domainName];
        }
        
        
        // Retrieve the supplied arguments for this domain
        NSDictionary *domainTrustKitArguments = TrustKitArguments[domainName];
        NSMutableDictionary *domainFinalConfiguration = [[NSMutableDictionary alloc]init];
        
        
        // Extract the optional includeSubdomains setting
        NSNumber *shouldIncludeSubdomains = domainTrustKitArguments[kTSKIncludeSubdomains];
        if (shouldIncludeSubdomains)
        {
            if ([shouldIncludeSubdomains boolValue] == YES)
            {
                // Prevent pinning on *.com
                // Ran into this issue with *.appspot.com which is part of the public suffix list
                if (GetRegistryLength([domainName UTF8String]) == [domainName length])
                {
                    [NSException raise:@"TrustKit configuration invalid"
                                format:@"TrustKit was initialized with includeSubdomains for a domain suffix %@", domainName];
                }
            }
            
            domainFinalConfiguration[kTSKIncludeSubdomains] = shouldIncludeSubdomains;
        }
        else
        {
            // Default setting is NO
            domainFinalConfiguration[kTSKIncludeSubdomains] = [NSNumber numberWithBool:NO];
        }

        
        // Extract the optional enforcePinning setting
        NSNumber *shouldEnforcePinning = domainTrustKitArguments[kTSKEnforcePinning];
        if (shouldEnforcePinning)
        {
            domainFinalConfiguration[kTSKEnforcePinning] = shouldEnforcePinning;
        }
        else
        {
            // Default setting is YES
            domainFinalConfiguration[kTSKEnforcePinning] = [NSNumber numberWithBool:YES];
        }
        
        
#if !TARGET_OS_IPHONE
        // OS X only: extract the optional ignorePinningForUserDefinedTrustAnchors setting
        NSNumber *shouldIgnorePinningForUserDefinedTrustAnchors = domainTrustKitArguments[kTSKIgnorePinningForUserDefinedTrustAnchors];
        if (shouldIgnorePinningForUserDefinedTrustAnchors)
        {
            domainFinalConfiguration[kTSKIgnorePinningForUserDefinedTrustAnchors] = shouldIgnorePinningForUserDefinedTrustAnchors;
        }
        else
        {
            // Default setting is YES
            domainFinalConfiguration[kTSKIgnorePinningForUserDefinedTrustAnchors] = [NSNumber numberWithBool:YES];
        }
#endif
        
        
        // Extract the optional disableDefaultReportUri setting
        NSNumber *shouldDisableDefaultReportUri = domainTrustKitArguments[kTSKDisableDefaultReportUri];
        if (shouldDisableDefaultReportUri)
        {
            domainFinalConfiguration[kTSKDisableDefaultReportUri] = shouldDisableDefaultReportUri;
        }
        else
        {
            // Default setting is NO
            domainFinalConfiguration[kTSKDisableDefaultReportUri] = [NSNumber numberWithBool:NO];
        }
        
        
        // Extract the list of public key algorithms to support and convert them from string to the TSKPublicKeyAlgorithm type
        NSArray *publicKeyAlgsStr = domainTrustKitArguments[kTSKPublicKeyAlgorithms];
        if (publicKeyAlgsStr == nil)
        {
            [NSException raise:@"TrustKit configuration invalid"
                        format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKPublicKeyAlgorithms, domainName];
        }
        NSMutableArray *publicKeyAlgs = [NSMutableArray array];
        for (NSString *algorithm in publicKeyAlgsStr)
        {
            if ([kTSKAlgorithmRsa2048 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:[NSNumber numberWithInt:TSKPublicKeyAlgorithmRsa2048]];
            }
            else if ([kTSKAlgorithmRsa4096 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:[NSNumber numberWithInt:TSKPublicKeyAlgorithmRsa4096]];
            }
            else if ([kTSKAlgorithmEcDsaSecp256r1 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:[NSNumber numberWithInt:TSKPublicKeyAlgorithmEcDsaSecp256r1]];
            }
            else
            {
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKPublicKeyAlgorithms, domainName];
            }
        }
        domainFinalConfiguration[kTSKPublicKeyAlgorithms] = [NSArray arrayWithArray:publicKeyAlgs];
        
        
        // Extract and convert the report URIs if defined
        NSArray *reportUriList = domainTrustKitArguments[kTSKReportUris];
        if (reportUriList != nil)
        {
            NSMutableArray *reportUriListFinal = [NSMutableArray array];
            for (NSString *reportUriStr in reportUriList)
            {
                NSURL *reportUri = [NSURL URLWithString:reportUriStr];
                if (reportUri == nil)
                {
                    [NSException raise:@"TrustKit configuration invalid"
                                format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKReportUris, domainName];
                }
                [reportUriListFinal addObject:reportUri];
            }
            
            domainFinalConfiguration[kTSKReportUris] = [NSArray arrayWithArray:reportUriListFinal];
        }
        
        
        // Extract and convert the subject public key info hashes
        NSArray *serverSslPinsBase64 = domainTrustKitArguments[kTSKPublicKeyHashes];
        if ([serverSslPinsBase64 count] < 2)
        {
            [NSException raise:@"TrustKit configuration invalid"
                        format:@"TrustKit was initialized with less than two pins (ie. no backup pins) for domain %@", domainName];
        }
        
        NSMutableArray *serverSslPinsData = [[NSMutableArray alloc] init];
        
        for (NSString *pinnedKeyHashBase64 in serverSslPinsBase64) {
            NSData *pinnedKeyHash = [[NSData alloc] initWithBase64EncodedString:pinnedKeyHashBase64 options:0];
            
            if ([pinnedKeyHash length] != CC_SHA256_DIGEST_LENGTH)
            {
                // The subject public key info hash doesn't have a valid size
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with an invalid Pin %@ for domain %@", pinnedKeyHashBase64, domainName];
            }
            
            [serverSslPinsData addObject:pinnedKeyHash];
        }
        
        // Save the hashes for this server as an NSSet for quick lookup
        domainFinalConfiguration[kTSKPublicKeyHashes] = [NSSet setWithArray:serverSslPinsData];
        
        // Store the whole configuration
        finalConfiguration[domainName] = [NSDictionary dictionaryWithDictionary:domainFinalConfiguration];
    }
    
    return finalConfiguration;
}


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
    
    dispatch_once(&dispatchOnceTrustKitInit, ^{
        if ([trustKitConfig count] > 0)
        {
            initializeSubjectPublicKeyInfoCache();
            
            // Convert and store the SSL pins in our global variable
            _trustKitGlobalConfiguration = [[NSDictionary alloc]initWithDictionary:parseTrustKitArguments(trustKitConfig)];
            
            // Hook SSLHandshake()
            if (original_SSLHandshake == NULL)
            {
                int rebindResult = -1;
                char functionToHook[] = "SSLHandshake";
                original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
                rebindResult = rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);
                if ((rebindResult < 0) || (original_SSLHandshake == NULL))
                {
                    [NSException raise:@"TrustKit initialization error"
                                format:@"Fishook returned an error: %d", rebindResult];
                }
            }
            
            // Create our reporter for sending pin validation failures
            @try
            {
                // Create a reporter that uses the background transfer service to send pin failure reports
                _pinFailureReporter = [[TSKBackgroundReporter alloc]initAndRateLimitReports:YES];
            
            }
            @catch (NSException *e)
            {
                // The bundle ID we get is nil if we're running tests on Travis so we have to use the simple reporter for unit tests
                TSKLog(@"Null bundle ID: we are running the test suite; falling back to TSKSimpleReporter");
                _pinFailureReporter = [[TSKSimpleReporter alloc]initAndRateLimitReports:YES];
            }
            
            // Create a dispatch queue for activating the reporter
            // We use a serial queue targetting the global default queue in order to ensure reports are sent one by one
            // even when a lot of pin failures are occuring, instead of spamming the global queue with events to process
            _pinFailureReporterQueue = dispatch_queue_create(kTSKPinFailureReporterQueueLabel, DISPATCH_QUEUE_SERIAL);
            dispatch_set_target_queue(_pinFailureReporterQueue, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));

            // All done
            _isTrustKitInitialized = YES;
            TSKLog(@"Successfully initialized with configuration %@", _trustKitGlobalConfiguration);
        }
    });
}


@implementation TrustKit


#pragma mark TrustKit Explicit Initialization

+ (void) initializeWithConfiguration:(NSDictionary *)trustKitConfig
{
    TSKLog(@"Configuration passed via explicit call to initializeWithConfiguration:");
    initializeTrustKit(trustKitConfig);
}


# pragma mark Private / Test Methods
+ (BOOL) wasTrustKitCalled
{
    return _wasTrustKitCalled;
}


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
    _wasTrustKitCalled = NO;
    _pinFailureReporter = nil;
    _pinFailureReporterQueue= NULL;
    dispatchOnceTrustKitInit = 0;
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
        initializeTrustKit(trustKitConfigFromInfoPlist);
    }
}



