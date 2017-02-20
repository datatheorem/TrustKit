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
        // The domain has no pinning policy: nothing to do/validate
        finalTrustDecision = TSKTrustDecisionDomainNotPinned;
    }
    else
    {
        // This domain has a pinning policy
        NSDictionary *domainConfig = trustKitConfig[kTSKPinnedDomains][domainConfigKey];
        
        // Has the pinning policy expired?
        NSDate *expirationDate = domainConfig[kTSKExpirationDate];
        if ((expirationDate != nil) && ([expirationDate compare:[NSDate date]] == NSOrderedAscending))
        {
            // Yes the policy has expired
            finalTrustDecision = TSKTrustDecisionDomainNotPinned;
            
        }
        else if ([domainConfig[kTSKExcludeSubdomainFromParentPolicy] boolValue])
        {
            // This is a subdomain that was explicitely excluded from the parent domain's policy
            finalTrustDecision = TSKTrustDecisionDomainNotPinned;
        }
        else
        {
            // The domain has a pinning policy that has not expired
            // Look for one the configured public key pins in the server's evaluated certificate chain
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
    }
    CFRelease(serverTrust);
    
    return finalTrustDecision;
}


+ (BOOL) handleChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
{
    BOOL wasChallengeHandled = NO;
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        // Check the trust object against the pinning policy
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
        
        TSKTrustDecision trustDecision = [TSKPinningValidator evaluateTrust:serverTrust forHostname:serverHostname];
        if (trustDecision == TSKTrustDecisionShouldAllowConnection)
        {
            // Success
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:serverTrust]);
        }
        else if (trustDecision == TSKTrustDecisionDomainNotPinned)
        {
            // Domain was not pinned; we need to do the default validation to avoid disabling SSL validation for all non-pinned domains
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        }
        else
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        }
    }
    return wasChallengeHandled;
}

@end
