/*
 
 TSKPinningValidator.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit+Private.h"


@implementation TSKPinningValidator

+ (TSKTrustDecision) evaluateTrust:(SecTrustRef _Nonnull)serverTrust forHostname:(NSString * _Nonnull)serverHostname
{
    TSKTrustDecision finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
    
    if ([TrustKit wasTrustKitInitialized] == NO)
    {
        [NSException raise:@"TrustKit not initialized"
                    format:@"TrustKit has not been initialized with a pinning configuration"];
    }
    
    if ((serverTrust == NULL) || (serverHostname == nil))
    {
        TSKLog(@"Pin validation error - invalid parameters for %@", serverHostname);
        return finalTrustDecision;
    }
    CFRetain(serverTrust);
    
    // Register start time for duration computations
    NSTimeInterval validationStartTime = [NSDate timeIntervalSinceReferenceDate];
    
    // Retrieve the pinning configuration for this specific domain, if there is one
    NSDictionary *trustKitConfig = [TrustKit configuration];
    NSString *domainConfigKey = getPinningConfigurationKeyForDomain(serverHostname, trustKitConfig);
    if (domainConfigKey == nil)
    {
        // The domain is not pinned: nothing to do/validate
        finalTrustDecision = TSKTrustDecisionDomainNotPinned;
    }
    else
    {
        // This domain is pinned: look for one the configured public key pins in the server's evaluated certificate chain
        NSDictionary *domainConfig = trustKitConfig[kTSKPinnedDomains][domainConfigKey];
        
        TSKPinValidationResult validationResult = verifyPublicKeyPin(serverTrust, serverHostname, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
        if (validationResult == TSKPinValidationResultSuccess)
        {
            // Pin validation was successful
            TSKLog(@"Pin validation succeeded for %@", serverHostname);
            finalTrustDecision = TSKTrustDecisionShouldAllowConnection;
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
            }
            else
#endif
            {
                if (validationResult == TSKPinValidationResultFailed)
                {
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
                else
                {
                    // Misc pinning errors (such as invalid certificate chain) - block the connection
                    finalTrustDecision = TSKTrustDecisionShouldBlockConnection;
                }
            }
        }
        // Send a notification after all validation is done; this will also trigger a report if pin validation failed
        NSTimeInterval validationDuration = [NSDate timeIntervalSinceReferenceDate] - validationStartTime;
        sendValidationNotification_async(serverHostname, serverTrust, domainConfigKey, validationResult, finalTrustDecision, validationDuration);
    }
    CFRelease(serverTrust);
    
    return finalTrustDecision;
}

@end
