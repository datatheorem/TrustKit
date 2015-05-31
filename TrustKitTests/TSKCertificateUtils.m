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
        [NSException raise:@"Test error" format:@"SecTrustCreateWithCertificates did not return errSecSuccess"];
    }
    
    if (anchorCertificates)
    {
        CFArrayRef trustStore = CFArrayCreate(NULL, (const void **)anchorCertificates, anchorArrayLength, NULL);
        
        if (SecTrustSetAnchorCertificates(trust, trustStore) != errSecSuccess)
        {
            [NSException raise:@"Test error" format:@"SecTrustCreateWithCertificates did not return errSecSuccess"];
        }
        CFRelease(trustStore);
    }
   
    CFRelease(certificateChain);
    return trust;
}

@end
