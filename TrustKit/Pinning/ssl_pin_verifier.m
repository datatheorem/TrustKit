/*
 
 ssl_pin_verifier.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "ssl_pin_verifier.h"
#import "TSKSPKIHashCache.h"
#import "../Dependencies/domain_registry/domain_registry.h"
#import "../configuration_utils.h"
#import "../TSKLog.h"


#pragma mark SSL Pin Verifier

TSKTrustEvaluationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverHostname, NSSet<NSData *> *knownPins, TSKSPKIHashCache *hashCache)
{
    NSCParameterAssert(serverTrust);
    NSCParameterAssert(knownPins);
    if ((serverTrust == NULL) || (knownPins == nil))
    {
        TSKLog(@"Invalid pinning parameters for %@", serverHostname);
        return TSKTrustEvaluationErrorInvalidParameters;
    }

    // First re-check the certificate chain using the default SSL validation in case it was disabled
    // This gives us revocation (only for EV certs I think?) and also ensures the certificate chain is sane
    // And also gives us the exact path that successfully validated the chain
    CFRetain(serverTrust);
    
    // Create and use a sane SSL policy to force hostname validation, even if the supplied trust has a bad
    // policy configured (such as one from SecPolicyCreateBasicX509())
    SecPolicyRef SslPolicy = SecPolicyCreateSSL(YES, (__bridge CFStringRef)(serverHostname));
    SecTrustSetPolicies(serverTrust, SslPolicy);
    CFRelease(SslPolicy);
    
    SecTrustResultType trustResult = 0;
    if (SecTrustEvaluate(serverTrust, &trustResult) != errSecSuccess)
    {
        TSKLog(@"SecTrustEvaluate error for %@", serverHostname);
        CFRelease(serverTrust);
        return TSKTrustEvaluationErrorInvalidParameters;
    }
    
    if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
    {
        // Default SSL validation failed
        CFDictionaryRef evaluationDetails = SecTrustCopyResult(serverTrust);
        TSKLog(@"Error: default SSL validation failed for %@: %@", serverHostname, evaluationDetails);
        CFRelease(evaluationDetails);
        CFRelease(serverTrust);
        return TSKTrustEvaluationFailedInvalidCertificateChain;
    }
    
    // Check each certificate in the server's certificate chain (the trust object); start with the CA all the way down to the leaf
    CFIndex certificateChainLen = SecTrustGetCertificateCount(serverTrust);
    for(int i=(int)certificateChainLen-1;i>=0;i--)
    {
        // Extract the certificate
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        CFStringRef certificateSubject = SecCertificateCopySubjectSummary(certificate);
        TSKLog(@"Checking certificate with CN: %@", certificateSubject);
        CFRelease(certificateSubject);
        
        // Generate the subject public key info hash
        NSData *subjectPublicKeyInfoHash = [hashCache hashSubjectPublicKeyInfoFromCertificate:certificate];
        if (subjectPublicKeyInfoHash == nil)
        {
            TSKLog(@"Error - could not generate the SPKI hash for %@", serverHostname);
            CFRelease(serverTrust);
            return TSKTrustEvaluationErrorCouldNotGenerateSpkiHash;
        }
        
        // Is the generated hash in our set of pinned hashes ?
        TSKLog(@"Testing SSL Pin %@", subjectPublicKeyInfoHash);
        if ([knownPins containsObject:subjectPublicKeyInfoHash])
        {
            TSKLog(@"SSL Pin found for %@", serverHostname);
            CFRelease(serverTrust);
            return TSKTrustEvaluationSuccess;
        }
    }
    
#if !TARGET_OS_IPHONE
    // OS X only: if user-defined anchors are whitelisted, allow the App to not enforce pin validation
    NSMutableArray *customRootCerts = [NSMutableArray array];
    
    // Retrieve the OS X host's list of user-defined CA certificates
    CFArrayRef userRootCerts;
    OSStatus status = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &userRootCerts);
    if (status == errSecSuccess)
    {
        [customRootCerts addObjectsFromArray:(__bridge NSArray *)(userRootCerts)];
        CFRelease(userRootCerts);
    }
    CFArrayRef adminRootCerts;
    status = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainAdmin, &adminRootCerts);
    if (status == errSecSuccess)
    {
        [customRootCerts addObjectsFromArray:(__bridge NSArray *)(adminRootCerts)];
        CFRelease(adminRootCerts);
    }
    
    // Is any certificate in the chain a custom anchor that was manually added to the OS' trust store ?
    // If we get there, we shouldn't have to check the custom certificates' trust setting (trusted / not trusted)
    // as the chain validation was successful right before
    if ([customRootCerts count] > 0)
    {
        for(int i=0;i<certificateChainLen;i++)
        {
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
            
            // Is the certificate chain's anchor a user-defined anchor ?
            if ([customRootCerts containsObject:(__bridge id)(certificate)])
            {
                TSKLog(@"Detected user-defined trust anchor in the certificate chain");
                CFRelease(serverTrust);
                return TSKTrustEvaluationFailedUserDefinedTrustAnchor;
            }
        }
    }
#endif
    
    // If we get here, we didn't find any matching SPKI hash in the chain
    TSKLog(@"Error: SSL Pin not found for %@", serverHostname);
    CFRelease(serverTrust);
    return TSKTrustEvaluationFailedNoMatchingPin;
}
