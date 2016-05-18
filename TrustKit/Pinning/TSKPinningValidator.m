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

    NSTimeInterval validationStartTime = 0;
    BOOL shouldPostNotifications = ([trustKitConfig[kTSKPostValidationNotifications] boolValue] == YES);
    if (shouldPostNotifications) {
        // Register start time for duration computations
        validationStartTime = [NSDate timeIntervalSinceReferenceDate];
    }

    TSKPinValidationResult validationResult = TSKPinValidationResultErrorInvalidParameters;

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
        
        validationResult = verifyPublicKeyPin(serverTrust, serverHostname, domainConfig[kTSKPublicKeyAlgorithms], domainConfig[kTSKPublicKeyHashes]);
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
    }

    // For consumers that want to get notified about all validations performed, post
    // a notification with duration and validation results/decision
    if (shouldPostNotifications) {
        NSTimeInterval validationDuration = [NSDate timeIntervalSinceReferenceDate] - validationStartTime;
        [[NSNotificationCenter defaultCenter] postNotificationName:kTSKValidationCompletedNotification
                                                            object:nil
                                                          userInfo:@{kTSKValidationDurationNotificationKey : @(validationDuration),
                                                                     kTSKValidationDecisionNotificationKey : @(finalTrustDecision),
                                                                     kTSKValidationResultNotificationKey   : @(validationResult)}];
    }

    return finalTrustDecision;
}

@end
