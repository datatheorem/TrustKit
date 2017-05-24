/*
 
 reporting_utils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "reporting_utils.h"


NSArray<NSString *> *convertTrustToPemArray(SecTrustRef serverTrust)
{
    // Convert the trust object into an array of PEM certificates
    // Warning: SecTrustEvaluate() always needs to be called first on the serverTrust to be able to extract the certificates
    NSMutableArray *certificateChain = [NSMutableArray array];
    CFIndex chainLen = SecTrustGetCertificateCount(serverTrust);
    for (CFIndex i=0;i<chainLen;i++)
    {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        CFDataRef certificateData = SecCertificateCopyData(certificate);
        
        // Craft the PEM certificate
        NSString *certificatePem = [NSString
                                    stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----",
                                    [(__bridge NSData *)certificateData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]];
        [certificateChain addObject:certificatePem];
        CFRelease(certificateData);
    }
    return certificateChain;
}


NSArray<NSString *> *convertPinsToHpkpPins(NSSet<NSData *> *knownPins)
{
    // Convert the know pins from a set of data to an array of strings as described in the HPKP spec
    NSMutableArray *formattedPins = [NSMutableArray array];
    for (NSData *pin in knownPins)
    {
        [formattedPins addObject:[NSString stringWithFormat:@"pin-sha256=\"%@\"", [pin base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)0]]];
    }
    return formattedPins;
}

