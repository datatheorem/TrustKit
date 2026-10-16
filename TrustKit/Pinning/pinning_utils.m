/*

 pinning_utils.m
 TrustKit

 Copyright 2023 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#import "pinning_utils.h"

void evaluateCertificateChainTrust(SecTrustRef serverTrust, SecTrustResultType *trustResult, NSError **error) {
    CFErrorRef errorRef;
    bool certificateEvaluationSucceeded = SecTrustEvaluateWithError(serverTrust, &errorRef);
    OSStatus status = SecTrustGetTrustResult(serverTrust, trustResult);
    if (error != NULL) {
        if (status != errSecSuccess)
        {
            NSString *errDescription = [NSString stringWithFormat:@"got status %d", (int)status];
            *error = [[NSError alloc] initWithDomain:@"com.datatheorem.trustkit" code:1 userInfo:@{NSLocalizedDescriptionKey:errDescription}];
        }
        else if (!certificateEvaluationSucceeded)
        {
            *error = (__bridge_transfer NSError *)errorRef;
        }
    }
}

SecCertificateRef getCertificateAtIndex(SecTrustRef serverTrust, CFIndex index) {
    CFArrayRef certs = SecTrustCopyCertificateChain(serverTrust);
    SecCertificateRef certificate = (SecCertificateRef)CFArrayGetValueAtIndex(certs, index);
    CFRelease(certs);
    return certificate;
}

SecKeyRef copyKey(SecTrustRef serverTrust) {
    return SecTrustCopyKey(serverTrust);
}
