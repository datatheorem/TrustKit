/*
 
 TSKCertificateUtils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKCertificateUtils.h"

@implementation TSKCertificateUtils

+ (SecCertificateRef)createCertificateFromDer:(NSString *)derCertiticatePath
{
    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
    CFDataRef certData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[bundle pathForResource:derCertiticatePath ofType:@"der"]];
    if (!certData)
    {
        [NSException raise:@"Test error" format:@"Could not open certificate at path %@", derCertiticatePath];
    }
    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, certData);
    CFRelease(certData);
    return certificate;
}


+ (SecTrustRef)createTrustWithCertificates:(const void **)certArray
                               arrayLength:(NSInteger)certArrayLength
                        anchorCertificates:(const void **)anchorCertificates
                               arrayLength:(NSInteger)anchorArrayLength
{
    CFArrayRef certificateChain = CFArrayCreate(NULL, (const void **)certArray, certArrayLength, NULL);
    SecTrustRef trust;
    
    SecPolicyRef policy = SecPolicyCreateSSL(true, NULL);
    
    if (SecTrustCreateWithCertificates(certificateChain, policy, &trust) != errSecSuccess)
    {
        if (certificateChain)
        {
            CFRelease(certificateChain);
        }
        CFRelease(policy);
        [NSException raise:@"Test error" format:@"SecTrustCreateWithCertificates did not return errSecSuccess"];
    }
    CFRelease(policy);
    
    if (anchorCertificates)
    {
        CFArrayRef trustStore = CFArrayCreate(NULL, (const void **)anchorCertificates, anchorArrayLength, NULL);
        
        if (SecTrustSetAnchorCertificates(trust, trustStore) != errSecSuccess)
        {
            if (certificateChain)
            {
                CFRelease(certificateChain);
            }
            
            if (trust)
            {
                CFRelease(trust);
            }
            [NSException raise:@"Test error" format:@"SecTrustCreateWithCertificates did not return errSecSuccess"];
        }
        CFRelease(trustStore);
    }
    
    CFRelease(certificateChain);

    // Certificates included in the test suite have certain expiration time window - between 11/3/15 and 3/29/16
    // Set the verify date to be in that range so the certs do not need to be updated periodically
    // The date we set to is 2016-01-22
    CFAbsoluteTime verifyTime = 475163640.0;
    CFDateRef testVerifyDate = CFDateCreate(NULL, verifyTime);
    SecTrustSetVerifyDate(trust, testVerifyDate);
    CFRelease(testVerifyDate);

    return trust;
}

@end
