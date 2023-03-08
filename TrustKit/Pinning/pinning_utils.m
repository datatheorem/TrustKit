/*

 pinning_utils.m
 TrustKit

 Copyright 2023 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#import <Foundation/Foundation.h>
#import "pinning_utils.h"

bool evaluateTrust(SecTrustRef serverTrust, SecTrustResultType *trustResult, NSError **error) {
    bool isTrusted = false;

    if (@available(iOS 12.0, macOS 14.0, *)) {
        CFErrorRef errorRef;
        isTrusted = SecTrustEvaluateWithError(serverTrust, &errorRef);
        OSStatus status = SecTrustGetTrustResult(serverTrust, trustResult);
        if (status != errSecSuccess)
        {
            isTrusted = false;
            NSString *errDescription = [NSString stringWithFormat:@"got status %d", status];
            *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:1 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
        }
        else if (!isTrusted && (error != NULL))
        {
            *error = (__bridge_transfer NSError *)errorRef;
        }
    }
    else
    {
        // Use pragmas to supress deprecated warnings
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        OSStatus status = SecTrustEvaluate(serverTrust, trustResult);
#pragma clang diagnostic pop
        if (status == errSecSuccess) {
            isTrusted = true;
        }
        else if (error != NULL){
            NSString *errDescription = [NSString stringWithFormat:@"got status %d", status];
            *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:2 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
        }
    }

    return isTrusted;
}

SecCertificateRef getCertificateAtIndex(SecTrustRef serverTrust, CFIndex index) {
    // Extract the certificate
    SecCertificateRef certificate;
    if (@available(macOS 12.0, iOS 15.0, *)) {
        CFArrayRef certs = SecTrustCopyCertificateChain(serverTrust);
        certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certs, index);
        CFRelease(certs);
    }
    else
    {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        certificate = SecTrustGetCertificateAtIndex(serverTrust, index);
#pragma clang diagnostic pop
    }
    return certificate;
}

SecKeyRef copyKey(SecTrustRef serverTrust) {
    if (@available(iOS 14.0, *)) {
        return SecTrustCopyKey(serverTrust);
    } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        return SecTrustCopyPublicKey(serverTrust);
#pragma clang diagnostic pop
    }
}
