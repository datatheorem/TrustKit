/*
 
 TSKPinningValidator.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinningValidator.h"
#import "ssl_pin_verifier.h"
#import "TrustKit+Private.h"



@implementation TSKPinningValidator

+ (TSKPinValidationResult) evaluateTrust:(SecTrustRef)serverTrust forHostname:(NSString *)serverHostname
{
    if ([TrustKit wasTrustKitInitialized] == NO)
    {
        [NSException raise:@"TrustKit not initialized"
                    format:@"TrustKit has not been initialized with a pinning configuration"];
    }
    
    if ((serverTrust == NULL) || (serverHostname == nil))
    {
        return TSKPinValidationResultErrorInvalidParameters;
    }
    
    TSKPinValidationResult validationResult = TSKPinValidationResultFailed;
    NSDictionary *trustKitConfig = [TrustKit configuration];
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverHostname, trustKitConfig);
    if (domainConfigKey == nil)
    {
        // The domain is not pinned: nothing to validate
        validationResult = TSKPinValidationResultDomainNotPinned;
    }
    else
    {
        // This domain is pinned: look for one the configured public key pins in the server's evaluated certificate chain
        CFRetain(serverTrust);
        NSDictionary *domainConfig = trustKitConfig[domainConfigKey];
        
        validationResult = verifyPublicKeyPin(serverTrust, serverHostname, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
        if (validationResult == TSKPinValidationResultSuccess)
        {
            // Pin validation was successful
            CFRelease(serverTrust);
        }
        else
        {
            // Pin validation failed
#if !TARGET_OS_IPHONE
            if ((validationResult == TSKPinValidationResultFailedUserDefinedTrustAnchor)
                && ([domainConfig[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue] == YES))
            {
                // OS-X only: user-defined trust anchors can be whitelisted (for corporate proxies, etc.) so don't send reports
                TSKLog(@"Ignoring pinning result for user-defined trust anchor");
                CFRelease(serverTrust);
            }
            else
#endif
            {
            // Send a pin failure report
            sendPinFailureReport_async(validationResult, serverTrust, serverHostname, domainConfigKey, domainConfig, ^void (void)
                                 {
                                     // Release the trust once the report has been sent
                                     CFRelease(serverTrust);
                                 });
            }
        }
    }
    return validationResult;
}

@end