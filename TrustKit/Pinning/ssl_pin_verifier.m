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



#pragma mark Utility functions

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


NSString *getPinningConfigurationKeyForDomain(NSString *hostname, NSDictionary *trustKitConfiguration)
{
    NSString *configHostname = nil;
    
    if (trustKitConfiguration[hostname] == nil)
    {
        // No pins explicitly configured for this domain
        // Look for an includeSubdomain pin that applies
        for (NSString *pinnedServerName in trustKitConfiguration)
        {
            // Check each domain configured with the includeSubdomain flag
            if ([trustKitConfiguration[pinnedServerName][kTSKIncludeSubdomains] boolValue])
            {
                // Is the server a subdomain of this pinned server?
                TSKLog(@"Checking includeSubdomains configuration for %@", pinnedServerName);
                if (isSubdomain(pinnedServerName, hostname))
                {
                    // Yes; let's use the parent domain's pinning configuration
                    TSKLog(@"Applying includeSubdomains configuration from %@ to %@", pinnedServerName, hostname);
                    configHostname = pinnedServerName;
                    break;
                }
            }
        }
    }
    else
    {
        // This hostname has a pinnning configuration
        configHostname = hostname;
    }
    
    if (configHostname == nil)
    {
        TSKLog(@"Domain %@ is not pinned", hostname);
    }
    return configHostname;
}


#pragma mark SSL Pin Verifier

TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverHostname, NSArray *supportedAlgorithms, NSSet *knownPins)
{
    if ((serverTrust == NULL) || (supportedAlgorithms == nil) || (knownPins == nil))
    {
        return TSKPinValidationResultFailedInvalidParameters;
    }
    
    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    // And also gives us the exact path that successfully validated the chain
    
    // Create and use a sane SSL policy to force hostname validation, even if the supplied trust has a bad
    // policy configured (such as one from SecPolicyCreateBasicX509())
    SecPolicyRef SslPolicy = SecPolicyCreateSSL(YES, (__bridge CFStringRef)(serverHostname));
    SecTrustSetPolicies(serverTrust, SslPolicy);
    
    SecTrustResultType trustResult = 0;
    if (SecTrustEvaluate(serverTrust, &trustResult) != errSecSuccess)
    {
        TSKLog(@"SecTrustEvaluate error");
        return TSKPinValidationResultFailedInvalidParameters;
    }
    
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        TSKLog(@"Error: default SSL validation failed");
        return TSKPinValidationResultFailedInvalidCertificateChain;
    }
    
    // Check each certificate in the server's certificate chain (the trust object)
    CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
    for(int i=0;i<certificateChainLen;i++)
    {
        // Extract the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        
        // For each public key algorithm flagged as supported in the config, generate the subject public key info hash
        for (id savedAlgorithm in supportedAlgorithms)
        {
            TSKPublicKeyAlgorithm algorithm = [savedAlgorithm integerValue];
            NSData *subjectPublicKeyInfoHash = hashSubjectPublicKeyInfoFromCertificate(certificate, algorithm);
            
            // Is the generated hash in our set of pinned hashes ?
            TSKLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
            if ([knownPins containsObject:subjectPublicKeyInfoHash])
            {
                TSKLog(@"SSL Pin found");
                return TSKPinValidationResultSuccess;
            }
        }
    }
    
    // If we get here, we didn't find any matching SPKI hash in the chain
    TSKLog(@"Error: SSL Pin not found");
    return TSKPinValidationResultFailed;
}
