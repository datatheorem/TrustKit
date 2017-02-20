//
//  parse_configuration.m
//  TrustKit
//
//  Created by Alban Diquet on 5/20/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TrustKit.h"
#import "Dependencies/domain_registry/domain_registry.h"
#import "parse_configuration.h"
#import "Pinning/public_key_utils.h"
#import <CommonCrypto/CommonDigest.h>
#import "configuration_utils.h"


NSDictionary *parseTrustKitConfiguration(NSDictionary *TrustKitArguments)
{
    // Convert settings supplied by the user to a configuration dictionary that can be used by TrustKit
    // This includes checking the sanity of the settings and converting public key hashes/pins from an
    // NSSArray of NSStrings (as provided by the user) to an NSSet of NSData (as needed by TrustKit)
    
    // Initialize domain registry library
    InitializeDomainRegistry();
    
    NSMutableDictionary *finalConfiguration = [[NSMutableDictionary alloc]init];
    finalConfiguration[kTSKPinnedDomains] = [[NSMutableDictionary alloc]init];
    
    
    // Retrieve global settings
    
    // Should we auto-swizzle network delegates
    NSNumber *shouldSwizzleNetworkDelegates = TrustKitArguments[kTSKSwizzleNetworkDelegates];
    if (shouldSwizzleNetworkDelegates == nil)
    {
        // This is a required argument
        [NSException raise:@"TrustKit configuration invalid"
                    format:@"TrustKit was initialized without specifying the kTSKSwizzleNetworkDelegates setting. Please add this boolean entry to the root of your TrustKit configuration in order to specify if auto-swizzling of the App's connection delegates should be enabled or not; see the documentation for more information."];
        // Default setting is YES
        finalConfiguration[kTSKSwizzleNetworkDelegates] = @(YES);
    }
    else
    {
        finalConfiguration[kTSKSwizzleNetworkDelegates] = shouldSwizzleNetworkDelegates;
    }
    
    
#if !TARGET_OS_IPHONE
    // OS X only: extract the optional ignorePinningForUserDefinedTrustAnchors setting
    NSNumber *shouldIgnorePinningForUserDefinedTrustAnchors = TrustKitArguments[kTSKIgnorePinningForUserDefinedTrustAnchors];
    if (shouldIgnorePinningForUserDefinedTrustAnchors == nil)
    {
        // Default setting is YES
        finalConfiguration[kTSKIgnorePinningForUserDefinedTrustAnchors] = @(YES);
    }
    else
    {
        finalConfiguration[kTSKIgnorePinningForUserDefinedTrustAnchors] = shouldIgnorePinningForUserDefinedTrustAnchors;
    }
#endif
    
    // Retrieve the pinning policy for each domains
    if ((TrustKitArguments[kTSKPinnedDomains] == nil) || ([TrustKitArguments[kTSKPinnedDomains] count] < 1))
    {
        [NSException raise:@"TrustKit configuration invalid"
                    format:@"TrustKit was initialized with no pinned domains. The configuration format has changed: ensure your domain pinning policies are under the TSKPinnedDomains key within TSKConfiguration."];
    }
    
    
    for (NSString *domainName in TrustKitArguments[kTSKPinnedDomains])
    {
        // Sanity checks on the domain name
        if (GetRegistryLength([domainName UTF8String]) == 0)
        {
            [NSException raise:@"TrustKit configuration invalid"
                        format:@"TrustKit was initialized with an invalid domain %@", domainName];
        }
        
        
        // Retrieve the supplied arguments for this domain
        NSDictionary *domainPinningPolicy = TrustKitArguments[kTSKPinnedDomains][domainName];
        NSMutableDictionary *domainFinalConfiguration = [[NSMutableDictionary alloc]init];
        
        
        // Always start with the optional excludeSubDomain setting; if it set, no other TSKDomainConfigurationKey can be set for this domain
        NSNumber *shouldExcludeSubdomain = domainPinningPolicy[kTSKExcludeSubdomainFromParentPolicy];
        if (shouldExcludeSubdomain)
        {
            // Confirm that no other TSKDomainConfigurationKeys were set for this domain
            if ([[domainPinningPolicy allKeys] count] > 1)
            {
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with TSKExcludeSubdomainFromParentPolicy for domain %@ but detected additional configuration keys", domainName];
            }
            
            // Store the whole configuration and continue to the next domain entry
            domainFinalConfiguration[kTSKExcludeSubdomainFromParentPolicy] = @(YES);
            finalConfiguration[kTSKPinnedDomains][domainName] = [NSDictionary dictionaryWithDictionary:domainFinalConfiguration];
            continue;
        }
        else
        {
            // Default setting is NO
            domainFinalConfiguration[kTSKExcludeSubdomainFromParentPolicy] = @(NO);
        }
        
        
        // Extract the optional includeSubdomains setting
        NSNumber *shouldIncludeSubdomains = domainPinningPolicy[kTSKIncludeSubdomains];
        if (shouldIncludeSubdomains == nil)
        {
            // Default setting is NO
            domainFinalConfiguration[kTSKIncludeSubdomains] = @(NO);
        }
        else
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
        
        
        // Extract the optional expiration date setting
        NSString *expirationDateStr = domainPinningPolicy[kTSKExpirationDate];
        if (expirationDateStr != nil)
        {
            // Convert the string in the yyyy-MM-dd format into an actual date
            NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
            [dateFormat setDateFormat:@"yyyy-MM-dd"];
            NSDate *expirationDate = [dateFormat dateFromString:expirationDateStr];
            domainFinalConfiguration[kTSKExpirationDate] = expirationDate;
        }
        
        
        // Extract the optional enforcePinning setting
        NSNumber *shouldEnforcePinning = domainPinningPolicy[kTSKEnforcePinning];
        if (shouldEnforcePinning)
        {
            domainFinalConfiguration[kTSKEnforcePinning] = shouldEnforcePinning;
        }
        else
        {
            // Default setting is YES
            domainFinalConfiguration[kTSKEnforcePinning] = @(YES);
        }

        
        // Extract the optional disableDefaultReportUri setting
        NSNumber *shouldDisableDefaultReportUri = domainPinningPolicy[kTSKDisableDefaultReportUri];
        if (shouldDisableDefaultReportUri)
        {
            domainFinalConfiguration[kTSKDisableDefaultReportUri] = shouldDisableDefaultReportUri;
        }
        else
        {
            // Default setting is NO
            domainFinalConfiguration[kTSKDisableDefaultReportUri] = @(NO);
        }
        
        
        // Extract the list of public key algorithms to support and convert them from string to the TSKPublicKeyAlgorithm type
        NSArray<NSString *> *publicKeyAlgsStr = domainPinningPolicy[kTSKPublicKeyAlgorithms];
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
                [publicKeyAlgs addObject:@(TSKPublicKeyAlgorithmRsa2048)];
            }
            else if ([kTSKAlgorithmRsa4096 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:@(TSKPublicKeyAlgorithmRsa4096)];
            }
            else if ([kTSKAlgorithmEcDsaSecp256r1 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:@(TSKPublicKeyAlgorithmEcDsaSecp256r1)];
            }
            else if ([kTSKAlgorithmEcDsaSecp384r1 isEqualToString:algorithm])
            {
                [publicKeyAlgs addObject:@(TSKPublicKeyAlgorithmEcDsaSecp384r1)];
            }
            else
            {
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with an invalid value for %@ for domain %@", kTSKPublicKeyAlgorithms, domainName];
            }
        }
        domainFinalConfiguration[kTSKPublicKeyAlgorithms] = [NSArray arrayWithArray:publicKeyAlgs];
        
        
        // Extract and convert the report URIs if defined
        NSArray<NSString *> *reportUriList = domainPinningPolicy[kTSKReportUris];
        if (reportUriList != nil)
        {
            NSMutableArray<NSURL *> *reportUriListFinal = [NSMutableArray array];
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
        NSArray<NSString *> *serverSslPinsBase64 = domainPinningPolicy[kTSKPublicKeyHashes];
        NSMutableSet<NSData *> *serverSslPinsSet = [NSMutableSet set];
        
        for (NSString *pinnedKeyHashBase64 in serverSslPinsBase64) {
            NSData *pinnedKeyHash = [[NSData alloc] initWithBase64EncodedString:pinnedKeyHashBase64 options:(NSDataBase64DecodingOptions)0];
            
            if ([pinnedKeyHash length] != CC_SHA256_DIGEST_LENGTH)
            {
                // The subject public key info hash doesn't have a valid size
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with an invalid Pin %@ for domain %@", pinnedKeyHashBase64, domainName];
            }
            
            [serverSslPinsSet addObject:pinnedKeyHash];
        }
        
        
        NSUInteger requiredNumberOfPins = [domainFinalConfiguration[kTSKEnforcePinning] boolValue] ? 2 : 1;
        if([serverSslPinsSet count] < requiredNumberOfPins)
        {
            [NSException raise:@"TrustKit configuration invalid"
                        format:@"TrustKit was initialized with less than %lu pins (ie. no backup pins) for domain %@. This might brick your App; please review the Getting Started guide in ./docs/getting-started.md", (unsigned long)requiredNumberOfPins, domainName];
        }
        
        // Save the hashes for this server as an NSSet for quick lookup
        domainFinalConfiguration[kTSKPublicKeyHashes] = [NSSet setWithSet:serverSslPinsSet];
        
        // Store the whole configuration
        finalConfiguration[kTSKPinnedDomains][domainName] = [NSDictionary dictionaryWithDictionary:domainFinalConfiguration];
    }
    
    
    // Lastly, ensure that we can find a parent policy for subdomains configured with TSKExcludeSubdomainFromParentPolicy
    for (NSString *domainName in finalConfiguration[kTSKPinnedDomains])
    {
        if ([finalConfiguration[kTSKPinnedDomains][domainName][kTSKExcludeSubdomainFromParentPolicy] boolValue])
        {
            // To force the lookup of a parent domain, we append 'a' to this subdomain so we don't retrieve its policy
            NSString *parentDomainConfigKey = getPinningConfigurationKeyForDomain([@"a" stringByAppendingString:domainName], finalConfiguration);
            if (parentDomainConfigKey == nil)
            {
                [NSException raise:@"TrustKit configuration invalid"
                            format:@"TrustKit was initialized with TSKExcludeSubdomainFromParentPolicy for domain %@ but could not find a policy for a parent domain", domainName];
            }
        }
    }

    return finalConfiguration;
}


