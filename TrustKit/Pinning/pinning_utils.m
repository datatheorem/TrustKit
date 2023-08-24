/*

 pinning_utils.m
 TrustKit

 Copyright 2023 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#import "pinning_utils.h"
#include <dlfcn.h>
#include "TargetConditionals.h"

void evaluateCertificateChainTrust(SecTrustRef serverTrust, SecTrustResultType *trustResult, NSError **error) {
    if (@available(iOS 12.0, macOS 14.0, tvOS 12.0, watchOS 5.0, *)) {
        CFErrorRef errorRef;
        bool certificateEvaluationSucceeded = SecTrustEvaluateWithError(serverTrust, &errorRef);
        OSStatus status = SecTrustGetTrustResult(serverTrust, trustResult);
        if (error != NULL) {
            if (status != errSecSuccess)
            {
                certificateEvaluationSucceeded = false;
                NSString *errDescription = [NSString stringWithFormat:@"got status %d", (int)status];
                *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:1 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
            }
            else if (!certificateEvaluationSucceeded)
            {
                *error = (__bridge_transfer NSError *)errorRef;
            }
        }
    }
    else
    {
        // Use pragmas to supress deprecated warnings
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus status = SecTrustEvaluate(serverTrust, trustResult);
#pragma clang diagnostic pop
        if (status != errSecSuccess && (error != NULL)) {
            NSString *errDescription = [NSString stringWithFormat:@"got status %d", (int)status];
            *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:2 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
        }
    }
}

SecCertificateRef getCertificateAtIndex(SecTrustRef serverTrust, CFIndex index) {
    NSInteger majorVersion = [[NSProcessInfo processInfo] operatingSystemVersion].majorVersion;
#if TARGET_OS_WATCH
    int osVersionThreshold = 8; // watchOS 8+
#elif TARGET_OS_IPHONE || TARGET_OS_SIMULATOR || TARGET_OS_IOS
    int osVersionThreshold = 15; // iOS 15+, tvOS 15+
#else
    int osVersionThreshold = 12; // macOS 12+
#endif
    SecCertificateRef certificate = NULL;
    void *_Security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW);

    if (majorVersion >= osVersionThreshold)
    {
        CFArrayRef (*_SecTrustCopyCertificateChain)(SecTrustRef) = dlsym(_Security, "SecTrustCopyCertificateChain");
        CFArrayRef certs = _SecTrustCopyCertificateChain(serverTrust);
        certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certs, index);
        CFRelease(certs);
    }
    else
    {
        SecCertificateRef (*_SecTrustGetCertificateAtIndex)(SecTrustRef, CFIndex) = dlsym(_Security, "SecTrustGetCertificateAtIndex");
        certificate = _SecTrustGetCertificateAtIndex(serverTrust, index);
    }
    return certificate;
}

SecKeyRef copyKey(SecTrustRef serverTrust) {
    if (@available(iOS 14.0, macOS 11.0, tvOS 14.0, watchOS 7.0, *)) {
        return SecTrustCopyKey(serverTrust);
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        return SecTrustCopyPublicKey(serverTrust);
#pragma clang diagnostic pop
    }
}
