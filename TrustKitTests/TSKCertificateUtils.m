//
//  TSKCertificateUtils.m
//  TrustKit
//
//  Created by Alban Diquet on 5/31/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TSKCertificateUtils.h"

@implementation TSKCertificateUtils

+ (SecCertificateRef)createCertificateFromDer:(NSString *)derCertiticatePath
{
    CFDataRef certData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]]
                                                                                      pathForResource:derCertiticatePath ofType:@"der"]];
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
        NSLog(@"SecTrustCreateWithCertificates did not return errSecSuccess");
        CFRelease(certificateChain);
        return NULL;
    }
    CFArrayRef trustStore = CFArrayCreate(NULL, (const void **)anchorCertificates, anchorArrayLength, NULL);
    
    if (SecTrustSetAnchorCertificates(trust, trustStore) != errSecSuccess)
    {
        NSLog(@"SecTrustSetAnchorCertificates did not return errSecSuccess");
        CFRelease(certificateChain);
        CFRelease(trustStore);
        return NULL;
        
    }
    CFRelease(certificateChain);
    CFRelease(trustStore);
    return trust;
}

@end
