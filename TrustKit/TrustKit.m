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



#pragma mark SSL Pin Validator

// TODO: Move this function to a separate file
BOOL verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverName, NSDictionary *TrustKitConfiguration)
{
    if ((serverTrust == NULL) || (serverName == NULL))
    {
        return NO;
    }
    
    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    // And also gives us the exact path that successfully validated the chain
    SecTrustResultType trustResult;
    SecTrustEvaluate(serverTrust, &trustResult);
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        NSLog(@"Error: default SSL validation failed");
        return NO;
    }
    
    // Let's find at least one of the pins in the certificate chain
    NSSet *serverPins = TrustKitConfiguration[serverName][kTSKPublicKeyHashes];
    

    // Check each certificate in the server's certificate chain (the trust object)
    CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
    for(int i=0;i<certificateChainLen;i++)
    {
        // Extract and hash the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        
        // For each public key algorithm flagged as supported in the config, generate the subject public key info hash
        for (id savedAlgorithm in TrustKitConfiguration[serverName][kTSKPublicKeyAlgorithms])
        {
            TSKPublicKeyAlgorithm algorithm = [savedAlgorithm integerValue];
            NSData *subjectPublicKeyInfoHash = hashSubjectPublicKeyInfoFromCertificate(certificate, algorithm);
            // TODO: error checking
            
            // Is the generated hash in our set of pinned hashes ?
            NSLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
            if ([serverPins containsObject:subjectPublicKeyInfoHash])
            {
                NSLog(@"SSL Pin found");
                return YES;
            }
        }
    }
    
    // If we get here, we didn't find any matching certificate in the chain
    NSLog(@"Error: SSL Pin not found");
    return NO;
}



#pragma mark SSLHandshake Hook

static OSStatus (*original_SSLHandshake)(SSLContextRef context);

static OSStatus replaced_SSLHandshake(SSLContextRef context)
{
    OSStatus result = original_SSLHandshake(context);
    if ((result == noErr) && (_isTrustKitInitialized))
    {
        // The handshake was sucessful, let's do our additional checks on the server certificate
        char *serverName = NULL;
        size_t serverNameLen = 0;
        // TODO: error handling
        
        // Get the server's domain name
        SSLGetPeerDomainNameLength (context, &serverNameLen);
        serverName = malloc(serverNameLen+1);
        SSLGetPeerDomainName(context, serverName, &serverNameLen);
        serverName[serverNameLen] = '\0';
        NSString *serverNameStr = [NSString stringWithUTF8String:serverName];
        free(serverName);
        
        
        if (_trustKitGlobalConfiguration == NULL)
        {   // TODO: return an error
            NSLog(@"Error: pin not initialized?");
            return NO;
        }
        
        
        // Is this domain name pinned ?
        BOOL wasPinValidationSuccessful = NO;
        if (_trustKitGlobalConfiguration[serverNameStr])
        {
            // Let's check the certificate chain with our SSL pins
            NSLog(@"Server IS pinned");
            SecTrustRef serverTrust;
            SSLCopyPeerTrust(context, &serverTrust);
            wasPinValidationSuccessful = verifyPublicKeyPin(serverTrust, serverNameStr, _trustKitGlobalConfiguration);
        }
        else
        {
            // No SSL pinning and regular SSL validation was already done by SSLHandshake and was sucessful
            NSLog(@"Server not pinned");
            wasPinValidationSuccessful = YES;
        }
        
        if (wasPinValidationSuccessful == NO)
        {
            if (_trustKitGlobalConfiguration[serverNameStr][kTSKEnforcePinning] != NO)
            {
                // TrustKit was configured to enforce pinning and the certificate chain did not contain the expected pins; force an error
                result = errSSLXCertChainInvalid;
            }
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
    
    NSMutableDictionary *finalConfiguration = [[NSMutableDictionary alloc]init];
    
    for (NSString *domainName in TrustKitArguments)
    {
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
            [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@", kTSKPublicKeyAlgorithms];
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
                [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@", kTSKPublicKeyAlgorithms];
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
                    [NSException raise:@"TrustKit configuration invalid" format:@"TrustKit was initialized with an invalid value for %@", kTSKReportUris];
                }
                [reportUriListFinal addObject:reportUri];
            }

            domainFinalConfiguration[kTSKReportUris] = [NSArray arrayWithArray:reportUriListFinal];
        }
        
        
        // Extract and convert the public key hashes
        NSArray *serverSslPinsString = domainTrustKitArguments[kTSKPublicKeyHashes];
        NSMutableArray *serverSslPinsData = [[NSMutableArray alloc] init];
        
        NSLog(@"Loading SSL pins for %@", domainName);
        for (NSString *pinnedCertificateHash in serverSslPinsString) {
            NSMutableData *pinnedCertificateHashData = [NSMutableData dataWithCapacity:CC_SHA256_DIGEST_LENGTH];
            
            // Convert the hex string to data
            if ([pinnedCertificateHash length] != CC_SHA256_DIGEST_LENGTH * 2) {
                // The public key hash doesn't have a valid size; store a null hash to make all connections fail
                NSLog(@"Bad hash for %@", domainName);
                [pinnedCertificateHashData resetBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH)];
            }
            else {
                // Convert the hash from NSString to NSData
                char output[CC_SHA256_DIGEST_LENGTH];
                const char *input = [pinnedCertificateHash UTF8String];
                
                for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                    sscanf(input + i * 2, "%2hhx", output + i);
                }
                [pinnedCertificateHashData replaceBytesInRange:NSMakeRange(0, CC_SHA256_DIGEST_LENGTH) withBytes:output];
            }
            
            [serverSslPinsData addObject:pinnedCertificateHashData];
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
        char functionToHook[] = "SSLHandshake";
        original_SSLHandshake = dlsym(RTLD_DEFAULT, functionToHook);
        rebind_symbols((struct rebinding[1]){{(char *)functionToHook, (void *)replaced_SSLHandshake}}, 1);

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


+ (void) resetConfiguration
{
    // This is only used for tests
    resetSubjectPublicKeyInfoCache();
    _trustKitGlobalConfiguration = nil;
    _isTrustKitInitialized = NO;
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



