//
//  reporting_utils.m
//  TrustKit
//
//  Created by Alban Diquet on 5/29/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>


NSArray *convertTrustToPemArray(SecTrustRef serverTrust)
{
    // Convert the trust object into an array of PEM certificates
    NSMutableArray *certificateChain = [NSMutableArray array];
    CFIndex chainLen = SecTrustGetCertificateCount(serverTrust);
    for (CFIndex i=0;i<chainLen;i++)
    {
        NSData *certificateData = (__bridge NSData *)(SecCertificateCopyData(SecTrustGetCertificateAtIndex(serverTrust, i)));
        [certificateChain addObject:[NSString stringWithFormat:@"-----BEGIN CERTIFICATE-----\n%@\n-----END CERTIFICATE-----", [certificateData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength]]];
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

