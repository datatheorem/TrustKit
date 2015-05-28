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


@implementation TSKPinVerifier

+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andDomain:(NSString *)serverHostname
{
    TSKPinValidationResult result = TSKPinValidationResultFailed;
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSDictionary *serverConfig = getPinningConfigurationForDomain(serverHostname, [TrustKit configuration]);
    if (serverConfig != nil)
    {
        // This domain is pinned: look for one the configured public key pins in the server's evaluated certificate chain
        result = verifyPublicKeyPin(serverTrust, serverConfig[kTSKPublicKeyAlgorithms], serverConfig[kTSKPublicKeyHashes]);
    }
    else
    {
        // The domain is not pinned: nothing to validate
        result = TSKPinValidationResultSuccess;
    }
    return result;
}

@end