/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"
#import "public_key_utils.h"
#import "parse_configuration.h"


NSString * const TrustKitVersion = @"1.4.0";

#pragma mark Configuration Constants

// Info.plist key we read the public key hashes from
static const NSString *kTSKConfiguration = @"TSKConfiguration";

// General keys
NSString * const kTSKPinnedDomains = @"TSKPinnedDomains";

// Keys for each domain within the TSKPinnedDomains entry
NSString * const kTSKPublicKeyHashes = @"TSKPublicKeyHashes";
NSString * const kTSKEnforcePinning = @"TSKEnforcePinning";
NSString * const kTSKIncludeSubdomains = @"TSKIncludeSubdomains";
NSString * const kTSKPublicKeyAlgorithms = @"TSKPublicKeyAlgorithms";
NSString * const kTSKIgnorePinningForUserDefinedTrustAnchors = @"TSKIgnorePinningForUserDefinedTrustAnchors";

#pragma mark Public key Algorithms Constants
NSString * const kTSKAlgorithmRsa2048 = @"TSKAlgorithmRsa2048";
NSString * const kTSKAlgorithmRsa4096 = @"TSKAlgorithmRsa4096";
NSString * const kTSKAlgorithmEcDsaSecp256r1 = @"TSKAlgorithmEcDsaSecp256r1";

#pragma mark TrustKit Global State
// Global dictionary for storing the public key hashes and domains
static NSDictionary *_trustKitGlobalConfiguration = nil;

// Global preventing multiple initializations (double method swizzling, etc.)
static BOOL _isTrustKitInitialized = NO;

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


#pragma mark TrustKit Initialization Helper Functions

static void initializeTrustKit(NSDictionary *trustKitConfig)
{
    if (trustKitConfig == nil)
    {
        return;
    }

    if ([trustKitConfig count] > 0)
    {
        [TrustKit resetConfiguration];
        
        initializeSubjectPublicKeyInfoCache();
        
        // Convert and store the SSL pins in our global variable
        _trustKitGlobalConfiguration = [[NSDictionary alloc]initWithDictionary:parseTrustKitConfiguration(trustKitConfig)];
        
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
