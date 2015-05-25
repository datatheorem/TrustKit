//
//  TSKPinVerifier.m
//  TrustKit
//
//  Created by Alban Diquet on 5/25/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TSKPinVerifier.h"
#import "ssl_pin_verifier.h"
#import "TrustKit+Private.h"

extern NSString * const kTSKPublicKeyHashes;


@implementation TSKPinVerifier

+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andDomain:(NSString *)serverHostname
{
    return verifyPublicKeyPin(serverTrust, serverHostname, [TrustKit trustKitConfiguration]);
}

@end