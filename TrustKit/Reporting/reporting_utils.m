/*
 
 reporting_utils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>

#import "reporting_utils.h"


NSArray<NSString *> *convertTrustToPemArray(SecTrustRef serverTrust)
{
    // Convert the trust object into an array of PEM certificates
    NSMutableArray *certificateChain = [NSMutableArray array];
    CFIndex chainLen = SecTrustGetCertificateCount(serverTrust);
    for (CFIndex i=0;i<chainLen;i++)
    {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        
        // Get the data and transfer ownership to ARC
        // Explicitly calling CFRelease() at the end of this function can crash the test suite
        NSData *certificateData = (NSData *)CFBridgingRelease(SecCertificateCopyData(certificate));
        
        // Craft the PEM certificate
        NSString *certificatePem = [NSString
                                    stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----",
                                    [certificateData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]];

        [certificateChain addObject:certificatePem];
    }
    return certificateChain;
}


NSArray<NSString *> *convertPinsToHpkpPins(NSArray<NSData *> *knownPins)
{
    // Convert the know pins from a set of data to an array of strings as described in the HPKP spec
    NSMutableArray *formattedPins = [NSMutableArray array];
    for (NSData *pin in knownPins)
    {
        [formattedPins addObject:[NSString stringWithFormat:@"pin-sha256=\"%@\"", [pin base64EncodedStringWithOptions:(NSDataBase64EncodingOptions)0]]];
    }
    return formattedPins;
}

