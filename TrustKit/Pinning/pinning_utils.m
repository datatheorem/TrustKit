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

bool evaluateTrust(SecTrustRef serverTrust, SecTrustResultType *trustResult, NSError **error) {
    CFErrorRef errorRef;
    bool isTrusted = SecTrustEvaluateWithError(serverTrust, &errorRef);
    OSStatus status = SecTrustGetTrustResult(serverTrust, trustResult);
    if (status != errSecSuccess)
    {
        isTrusted = false;
        NSString *errDescription = [NSString stringWithFormat:@"got status %d", status];
        if (error != NULL) {
            *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:1 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
        }
    }
    else if (!isTrusted && (error != NULL))
    {
        *error = (__bridge_transfer NSError *)errorRef;
    }
    return isTrusted;
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
    void *_Security = dlopen("Security.framework/Security", RTLD_NOW);
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
