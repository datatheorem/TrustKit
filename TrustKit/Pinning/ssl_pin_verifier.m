//
//  ssl_pin_verifier.m
//  TrustKit
//
//  Created by Alban Diquet on 4/23/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//


#import "ssl_pin_verifier.h"
#import "domain_registry.h"
#import "public_key_utils.h"
#import "TrustKit+Private.h"


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
            if ([TrustKitConfiguration[pinnedServerName][kTSKIncludeSubdomains] boolValue])
            {
                // Is the server a subdomain of this pinned server?
                TSKLog(@"Checking includeSubdomains configuration for %@", pinnedServerName);
                if (isSubdomain(pinnedServerName, serverName))
                {
                    // Yes; let's use the parent domain's pins
                    TSKLog(@"Applying includeSubdomains configuration from %@ to %@", pinnedServerName, serverName);
                    serverPinningConfiguration = TrustKitConfiguration[pinnedServerName];
                    break;
                }
            }
        }
    }
    
    // If this domain isn't pinned the validation always succeeds
    if (serverPinningConfiguration == nil)
    {
        TSKLog(@"Domain %@ is not pinned", serverName);
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
        TSKLog(@"SecTrustEvaluate error");
        return TSKPinValidationResultInvalidParameters;
    }
    
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        TSKLog(@"Error: default SSL validation failed");
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
            
            // Is the generated hash in our set of pinned hashes ?
            TSKLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
            if ([serverPins containsObject:subjectPublicKeyInfoHash])
            {
                TSKLog(@"SSL Pin found");
                return TSKPinValidationResultSuccess;
            }
        }
    }
    
    
    // If we get here, we didn't find any matching SPKI hash in the chain
    TSKLog(@"Error: SSL Pin not found");
    if ([serverPinningConfiguration[kTSKEnforcePinning] boolValue] == YES)
    {
        // TrustKit was configured to enforce pinning; force an error
        return TSKPinValidationResultFailed;
    }
    
    // TrustKit was configured to not enforce pinning for this domain; don't return an error
    return TSKPinValidationResultPinningNotEnforced;
}
