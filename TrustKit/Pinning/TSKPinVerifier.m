/*
 
 TSKPinVerifier.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinVerifier.h"
#import "ssl_pin_verifier.h"
#import "TrustKit+Private.h"


@implementation TSKPinVerifier

+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andHostname:(NSString *)serverHostname
{
    TSKPinValidationResult result = TSKPinValidationResultFailed;
    NSDictionary *trustKitConfig = [TrustKit configuration];
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverHostname, trustKitConfig);
    if (domainConfigKey != nil)
    {
        // This domain is pinned: look for one the configured public key pins in the server's evaluated certificate chain
        NSDictionary *domainConfig = trustKitConfig[domainConfigKey];
        result = verifyPublicKeyPin(serverTrust, serverHostname, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
    }
    else
    {
        // The domain is not pinned: nothing to validate
        result = TSKPinValidationResultSuccess;
    }
    return result;
}

@end