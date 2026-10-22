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

static BOOL readDERElement(const uint8_t *element, const uint8_t *end, uint8_t *tag, const uint8_t **content, const uint8_t **next) {
    if (end - element < 2) {
        return NO;
    }
    *tag = element[0];
    const uint8_t *cursor = element + 2;
    size_t length = element[1];
    if (length & 0x80) {
        // DER has no indefinite length (0x80), and certificate lengths fit in 4 bytes
        size_t lengthBytes = length & 0x7f;
        if (lengthBytes == 0 || lengthBytes > 4 || (size_t)(end - cursor) < lengthBytes) {
            return NO;
        }
        length = 0;
        for (size_t i = 0; i < lengthBytes; i++) {
            length = (length << 8) | *cursor++;
        }
    }
    if ((size_t)(end - cursor) < length) {
        return NO;
    }
    *content = cursor;
    *next = cursor + length;
    return YES;
}

NSData *getSubjectPublicKeyInfo(NSData *certificateData) {
    const uint8_t *cursor = certificateData.bytes;
    const uint8_t *end = cursor + certificateData.length;
    uint8_t tag;
    const uint8_t *content, *next;

    // Step into the Certificate and tbsCertificate SEQUENCEs
    for (int i = 0; i < 2; i++) {
        if (!readDERElement(cursor, end, &tag, &content, &next) || tag != 0x30) {
            return nil;
        }
        cursor = content;
        end = next;
    }

    // RFC 5280 4.1: an optional [0] version, then serialNumber, signature, issuer, validity and subject
    if (readDERElement(cursor, end, &tag, &content, &next) && tag == 0xa0) {
        cursor = next;
    }
    const uint8_t skippedTags[] = {0x02, 0x30, 0x30, 0x30, 0x30};
    for (size_t i = 0; i < sizeof(skippedTags); i++) {
        if (!readDERElement(cursor, end, &tag, &content, &next) || tag != skippedTags[i]) {
            return nil;
        }
        cursor = next;
    }

    if (!readDERElement(cursor, end, &tag, &content, &next) || tag != 0x30) {
        return nil;
    }
    return [NSData dataWithBytes:cursor length:(NSUInteger)(next - cursor)];
}
