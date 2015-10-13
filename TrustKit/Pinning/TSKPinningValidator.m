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

+ (TSKTrustDecision) evaluateTrust:(SecTrustRef)serverTrust forHostname:(NSString *)serverHostname
{
    if ([TrustKit wasTrustKitInitialized] == NO)
    {
        [NSException raise:@"TrustKit not initialized"
                    format:@"TrustKit has not been initialized with a pinning configuration"];
    }
    
    if ((serverTrust == NULL) || (serverHostname == nil))
    {
        TSKLog(@"Pin validation error - invalid parameters for %@", serverHostname);
        return TSKTrustDecisionShouldBlockConnection;
    }
    
    TSKTrustDecision finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
    NSDictionary *trustKitConfig = [TrustKit configuration];
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverHostname, trustKitConfig);
    if (domainConfigKey == nil)
    {
        // The domain is not pinned: nothing to validate
        finalTrustDecision = TSKTrustDecisionDomainNotPinned;
    }
    else
    {
        // This domain is pinned: look for one the configured public key pins in the server's evaluated certificate chain
        CFRetain(serverTrust);
        NSDictionary *domainConfig = trustKitConfig[kTSKPinnedDomains][domainConfigKey];
        
        TSKPinValidationResult validationResult = verifyPublicKeyPin(serverTrust, serverHostname, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
        if (validationResult == TSKPinValidationResultSuccess)
        {
            // Pin validation was successful
            TSKLog(@"Pin validation succeeded for %@", serverHostname);
            finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
            CFRelease(serverTrust);
        }
        else
        {
            // Pin validation failed
            TSKLog(@"Pin validation failed for %@", serverHostname);
#if !TARGET_OS_IPHONE
            if ((validationResult == TSKPinValidationResultFailedUserDefinedTrustAnchor)
                && ([trustKitConfig[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue] == YES))
            {
                // OS-X only: user-defined trust anchors can be whitelisted (for corporate proxies, etc.) so don't send reports
                TSKLog(@"Ignoring pinning failure due to user-defined trust anchor for %@", serverHostname);
                finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
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
                
                // Is pinning enforced?
                if ([domainConfig[kTSKEnforcePinning] boolValue] == YES)
                {
                    // Yes - Block the connection
                    finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
                }
                else
                {
                    finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
                }
            }
        }
    }
    return finalTrustDecision;
}

@end