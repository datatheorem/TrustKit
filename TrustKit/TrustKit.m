//
//  TrustKit.m
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TrustKit.h"
#import "TrustKit+Private.h"
#include <dlfcn.h>
#import <CommonCrypto/CommonDigest.h>
#import "fishhook/fishhook.h"
#import "subjectPublicKeyHash.h"
#import "domain_registry.h"


// Info.plist key we read the public key hashes from
static NSString * const kTSKConfiguration = @"TSKConfiguration";

// Keys for each domain within the config dictionnary
NSString * const kTSKPublicKeyHashes = @"TSKPublicKeyHashes";
NSString * const kTSKEnforcePinning = @"TSKEnforcePinning";
NSString * const kTSKIncludeSubdomains = @"TSKIncludeSubdomains";
NSString * const kTSKPublicKeyAlgorithms = @"TSKPublicKeyAlgorithms";
NSString * const kTSKReportUris = @"TSKReportUris";

// Public key algorithms supported by TrustKit
NSString * const kTSKAlgorithmRsa2048 = @"TSKAlgorithmRsa2048";
NSString * const kTSKAlgorithmRsa4096 = @"TSKAlgorithmRsa4096";
NSString * const kTSKAlgorithmEcDsaSecp256r1 = @"TSKAlgorithmEcDsaSecp256r1";


#pragma mark TrustKit Global State
// Global dictionnary for storing the public key hashes and domains
static NSDictionary *_trustKitGlobalConfiguration = nil;

// Global preventing multiple initializations (double function interposition, etc.)
static BOOL _isTrustKitInitialized = NO;

// For tests
static BOOL _wasTrustKitCalled = NO;



#pragma mark SSL Pin Validator

static BOOL isSubdomain(NSString *domain, NSString *subdomain)
{
    size_t domainRegistryLength = GetRegistryLength([domain UTF8String]);
    if (GetRegistryLength([subdomain UTF8String]) != domainRegistryLength)
    {
        // Different TLDs
        return NO;
    }
    
    // Retrieve the main domain without the TLD
    NSString *domainLabel = [domain substringToIndex:([domain length] - domainRegistryLength - 1)];
    
    // Retrieve the subdomain's domain without the TLD
    NSString *subdomainLabel = [subdomain substringToIndex:([subdomain length] - domainRegistryLength - 1)];
    
    if ([subdomainLabel rangeOfString:domainLabel].location != NSNotFound)
    {
        // This is a subdomain
        return YES;
    }
    return NO;
}


// TODO: Move this function to a separate file
TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverName, NSDictionary *TrustKitConfiguration)
{
    if ((serverTrust == NULL) || (serverName == NULL))
    {
        return TSKPinValidationResultInvalidParameters;
    }
    
    // First let's figure out if this domain is pinned
    // Do we have this specific domain explicitely pinned ?
    NSDictionary *serverPinningConfiguration = TrustKitConfiguration[serverName];
    
    
    // No pins explicitly configured for this domain
    if (serverPinningConfiguration == nil)
    {
        // Look for an includeSubdomain pin that applies
        for (NSString *pinnedServerName in TrustKitConfiguration)
        {
            // Check each domain configured with the includeSubdomain flag
            if (TrustKitConfiguration[pinnedServerName][kTSKIncludeSubdomains])
            {
                // Is the server a subdomain of this pinned server?
                NSLog(@"Checking includeSubdomains configuration for %@", pinnedServerName);
                if (isSubdomain(pinnedServerName, serverName))
                {
                    // Yes; let's use the parent domain's pins
                    NSLog(@"Applying includeSubdomains configuration from %@ to %@", pinnedServerName, serverName);
                    serverPinningConfiguration = TrustKitConfiguration[pinnedServerName];
                    break;
                }
            }
        }
    }
    
    // If this domain isn't pinned the validation always succeeds
    if (serverPinningConfiguration == nil)
    {
        NSLog(@"Domain %@ is not pinned", serverName);
        return TSKPinValidationResultDomainNotPinned;
    }
    
    // Domain is pinned
    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    // And also gives us the exact path that successfully validated the chain
    NSSet *serverPins = serverPinningConfiguration[kTSKPublicKeyHashes];
    
    SecTrustResultType trustResult = 0;
    if (SecTrustEvaluate(serverTrust, &trustResult) != errSecSuccess)
    {
        NSLog(@"SecTrustEvaluate error");
        return TSKPinValidationResultInvalidParameters;
    }
    
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        NSLog(@"Error: default SSL validation failed");
        return TSKPinValidationResultInvalidCertificateChain;
    }
    
    // Check each certificate in the server's certificate chain (the trust object)
    CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
    for(int i=0;i<certificateChainLen;i++)
    {
        // Extract the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        
        // For each public key algorithm flagged as supported in the config, generate the subject public key info hash
        for (id savedAlgorithm in serverPinningConfiguration[kTSKPublicKeyAlgorithms])
        {
            TSKPublicKeyAlgorithm algorithm = [savedAlgorithm integerValue];
            NSData *subjectPublicKeyInfoHash = hashSubjectPublicKeyInfoFromCertificate(certificate, algorithm);
            // TODO: error checking
            
            // Is the generated hash in our set of pinned hashes ?
            NSLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
            if ([serverPins containsObject:subjectPublicKeyInfoHash])
            {
                NSLog(@"SSL Pin found");
                return TSKPinValidationResultSuccess;
            }
        }
    }
    

    // If we get here, we didn't find any matching SPKI hash in the chain
    NSLog(@"Error: SSL Pin not found");
    if ([serverPinningConfiguration[kTSKEnforcePinning] boolValue] == YES)
    {
        // TrustKit was configured to enforce pinning; force an error
        return TSKPinValidationResultFailed;
    }
    
    // TrustKit was configured to not enforce pinning for this domain; don't return an error
    return TSKPinValidationResultPinningNotEnforced;
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
        
        // Verify the server's certificate if it is pinned
        SecTrustRef serverTrust;
        SSLCopyPeerTrust(context, &serverTrust);
        
        TSKPinValidationResult validationResult = verifyPublicKeyPin(serverTrust, serverNameStr, _trustKitGlobalConfiguration);
        
        if (!
            ((validationResult == TSKPinValidationResultSuccess)
            || (validationResult == TSKPinValidationResultDomainNotPinned)
            || (validationResult == TSKPinValidationResultPinningNotEnforced)))
        {
            // Validation failed
            result = errSSLXCertChainInvalid;
        }
    }
    return result;
}


#pragma mark Framework Initialization


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
        // Sanity check on the domain name
        if (GetRegistryLength([domainName UTF8String]) == 0)
        {
            [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid domain %@", domainName];
        }
        
        
        // Retrieve the supplied arguments for this domain
        NSDictionary *domainTrustKitArguments = TrustKitArguments[domainName];
        NSMutableDictionary *domainFinalConfiguration = [[NSMutableDictionary alloc]init];
        
        
        // Extract the optional includeSubdomains setting
        NSNumber *shouldIncludeSubdomains = domainTrustKitArguments[kTSKIncludeSubdomains];
        if (shouldIncludeSubdomains)
        {
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
        
        
        // Extract the list of public key algorithms to support and convert them from string to the TSKPublicKeyAlgorithm type
        NSArray *publicKeyAlgsStr = domainTrustKitArguments[kTSKPublicKeyAlgorithms];
        if (publicKeyAlgsStr == nil)
        {
            [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKPublicKeyAlgorithms, domainName];
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
                [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKPublicKeyAlgorithms, domainName];
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
                    [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKReportUris, domainName];
                }
                [reportUriListFinal addObject:reportUri];
            }
            
            domainFinalConfiguration[kTSKReportUris] = [NSArray arrayWithArray:reportUriListFinal];
        }
        
        
        // Extract and convert the public key hashes
        NSArray *serverSslPinsBase64 = domainTrustKitArguments[kTSKPublicKeyHashes];
        
        NSMutableArray *serverSslPinsData = [[NSMutableArray alloc] init];
        
        for (NSString *pinnedKeyHashBase64 in serverSslPinsBase64) {
            NSData *pinnedKeyHash = [[NSData alloc] initWithBase64EncodedString:pinnedKeyHashBase64 options:0];
            
            if ([pinnedKeyHash length] != CC_SHA256_DIGEST_LENGTH)
            {
                // The public key hash doesn't have a valid size
                [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid Pin %@ for domain %@", pinnedKeyHashBase64, domainName];
            }
            
            [serverSslPinsData addObject:pinnedKeyHash];
        }
        
        // Save the public key hashes for this server as an NSSet for quick lookup
        domainFinalConfiguration[kTSKPublicKeyHashes] = [NSSet setWithArray:serverSslPinsData];
        
        // Store the whole configuration
        finalConfiguration[domainName] = [NSDictionary dictionaryWithDictionary:domainFinalConfiguration];
    }
    
    return finalConfiguration;
}


static void initializeTrustKit(NSDictionary *TrustKitConfig)
{
    if (TrustKitConfig == nil)
    {
        return;
    }
    
    if (_isTrustKitInitialized == YES)
    {
        // TrustKit should only be initialized once so we don't double interpose SecureTransport or get into anything unexpected
        [NSException raise:@"TrustKit already initialized" format:@"TrustKit was already initialized with the following SSL pins: %@", _trustKitGlobalConfiguration];
    }
    
    if ([TrustKitConfig count] > 0)
    {
        initializeSubjectPublicKeyInfoCache();
        
        // Convert and store the SSL pins in our global variable
        _trustKitGlobalConfiguration = [[NSDictionary alloc]initWithDictionary:parseTrustKitArguments(TrustKitConfig)];
        
        // Hook SSLHandshake()
        if (original_SSLHandshake == NULL)
        {
            int rebindResult = -1;
            char functionToHook[] = "SSLHandshake";
            original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
            rebindResult = rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);
            if ((rebindResult < 0) || (original_SSLHandshake == NULL))
            {
                [NSException raise:@"TrustKit initialization error" format:@"Fishook returned an error: %d", rebindResult];
            }
        }
        
        _isTrustKitInitialized = YES;
        NSLog(@"TrustKit initialized with configuration %@", _trustKitGlobalConfiguration);
    }
}


#pragma mark Framework Initialization When Statically Linked

@implementation TrustKit


+ (void) initializeWithConfiguration:(NSDictionary *)TrustKitConfig
{
    NSLog(@"TrustKit started statically in App %@", CFBundleGetValueForInfoDictionaryKey(CFBundleGetMainBundle(), (__bridge CFStringRef)@"CFBundleIdentifier"));
    initializeTrustKit(TrustKitConfig);
}

+ (BOOL) wasTrustKitCalled
{
    return _wasTrustKitCalled;
}


+ (void) resetConfiguration
{
    // This is only used for tests
    resetSubjectPublicKeyInfoCache();
    _trustKitGlobalConfiguration = nil;
    _isTrustKitInitialized = NO;
    _wasTrustKitCalled = NO;
}

@end


#pragma mark Framework Initialization When Dynamically Linked

__attribute__((constructor)) static void initialize(int argc, const char **argv)
{
    // TrustKit just got injected in the App
    CFBundleRef appBundle = CFBundleGetMainBundle();
    NSLog(@"TrustKit started dynamically in App %@", CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)@"CFBundleIdentifier"));
    
    // Retrieve the configuration from the App's Info.plist file
    NSDictionary *trustKitConfigFromInfoPlist = CFBundleGetValueForInfoDictionaryKey(appBundle, (__bridge CFStringRef)kTSKConfiguration);
    
    initializeTrustKit(trustKitConfigFromInfoPlist);
}



