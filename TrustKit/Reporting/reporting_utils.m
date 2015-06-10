/*
 
 reporting_utils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>


NSArray *convertTrustToPemArray(SecTrustRef serverTrust)
{
    // Convert the trust object into an array of PEM certificates
    NSMutableArray *certificateChain = [NSMutableArray array];
    CFIndex chainLen = SecTrustGetCertificateCount(serverTrust);
    for (CFIndex i=0;i<chainLen;i++)
    {
        CFDataRef certificateData = SecCertificateCopyData(SecTrustGetCertificateAtIndex(serverTrust, i));
        [certificateChain addObject:[NSString
                                     stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----",
                                     [(__bridge NSData *)(certificateData) base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]]];
        CFRelease(certificateData);
    }
    return certificateChain;
}


NSArray *convertPinsToHpkpPins(NSArray *knownPins)
{
    // Convert the know pins from a set of data to an array of strings as described in the HPKP spec
    NSMutableArray *formattedPins = [NSMutableArray array];
    for (NSData *pin in knownPins)
    {
        [formattedPins addObject:[NSString stringWithFormat:@"pin-sha256=\"%@\"", [pin base64EncodedStringWithOptions:0]]];
    }
    return formattedPins;
}

