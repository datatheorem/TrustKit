/*
 
 TSKPinningValidator.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>



/**
 Possible return values when verifying a server's identity against the global SSL pinning policy using `TSKPinningValidator`.
 
 */
typedef NS_ENUM(NSInteger, TSKTrustDecision)
{
/**
 Based on the server's certificate chain and the global pinning policy for this domain, the SSL connection should be allowed.
 This return value does not necessarily mean that the pinning validation succeded (for example if `kTSKEnforcePinning` was set to `NO` for this domain). If a pinning validation failure occured and if a report URI was configured, a pin failure report was sent.
 */
    TSKTrustDecisionShouldAllowConnection,
    
/**
 Based on the server's certificate chain and the global pinning policy for this domain, the SSL connection should be blocked.
 A pinning validation failure occured and if a report URI was configured, a pin failure report was sent.
 */
    TSKTrustDecisionShouldBlockConnection,
    
/**
 No pinning policy was configured for this domain and TrustKit did not validate the server's identity.
 Because this will happen in an authentication handler, it means that the server's _serverTrust_ object __needs__ to be verified against the device's trust store using `SecTrustEvaluate()`. Failing to do so will __disable SSL certificate validation__.
 */
    TSKTrustDecisionDomainNotPinned,
};


/**
 `TSKPinningValidator` is a class for manually verifying a server's identity against the global SSL pinning policy.
 
 In specific scenarios, TrustKit cannot intercept outgoing SSL connections and automatically validate the server's identity against the pinning policy. For these connections, the pin validation must be manually triggered: the server's `SecTrustRef` object, which contains its certificate chain, needs to be retrieved or built before being passed to `TSKPinningValidator` for validation.
 
 `TSKPinningValidator` returns a `TSKTrustDecision` which describes whether the SSL connection should be allowed or blocked, based on the global pinning policy.
 
 The following connections require manual pin validation:
 
 1. All connections within an App that disables TrustKit's network delegate swizzling by setting the `kTSKSwizzleNetworkDelegates` configuration key to `NO`.
 2. Connections that do not rely on the `NSURLConnection` or `NSURLSession` APIs:
     * Connections leveraging lower-level APIs (such as `NSStream`). Instructions on how to retrieve the server's trust object are available at https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html.
     * Connections initiated using a third-party SSL library such as OpenSSL. The server's `SecTrustRef` object needs to be built using the received certificate chain.
 3. Connections happening within an external process:
     * `WKWebView` connections: the server's `SecTrustRef` object can be retrieved and validated within the `webView:didReceiveAuthenticationChallenge:completionHandler:` method.
     * `NSURLSession` connections using the background transfer service: the server's `SecTrustRef` object can be retrieved and validated within the `application:handleEventsForBackgroundURLSession:completionHandler:` method.
 
 For example, `TSKPinningValidator` should be used as follow when verifying the server's identity within an `NSURLSession` or `WKWebView` authentication handler:
 
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        // Check the trust object against the pinning policy
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
        
        TSKTrustDecision trustDecision = [TSKPinningValidator evaluateTrust:serverTrust 
                                                                forHostname:serverHostname];
        
        if (trustDecision == TSKTrustDecisionShouldAllowConnection)
        {
            // Success
            completionHandler(NSURLSessionAuthChallengeUseCredential, 
                              [NSURLCredential credentialForTrust:serverTrust]);
        }
        else if (trustDecision == TSKTrustDecisionDomainNotPinned)
        {
            // Domain was not pinned; we need to do the default validation ourselves to avoid disabling
            // SSL validation for all non-pinned domains
            SecTrustResultType trustResult = 0;
            SecTrustEvaluate(serverTrust, &trustResult);
            if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
            {
                // Default SSL validation failed - block the connection
                completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
            }
            else
            {
                // Default SSL validation succeeded
                completionHandler(NSURLSessionAuthChallengeUseCredential, 
                                  [NSURLCredential credentialForTrust:serverTrust]);
            }
        }
        else
        {
            // Pinning validation failed - block the connection
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        }
    }
 
 
 */
NS_ASSUME_NONNULL_BEGIN
@interface TSKPinningValidator : NSObject

///------------------------------------
/// @name Manual SSL Pinning Validation
///------------------------------------

/**
 Evaluate the supplied server trust against the global SSL pinning policy previously configured. If the validation fails, pin failure reports will be sent accordingly.
 
 @param serverTrust The trust object representing the server's certificate chain. The trust's evaluation policy is always overridden using `SecTrustSetPolicies()` to ensure all the proper SSL checks (expiration, hostname validation, etc.) are enabled.
 
 @param serverHostname The hostname of the server whose identity is being validated.
 
 @return A `TSKTrustDecision` which describes whether the SSL connection should be allowed or blocked, based on the global pinning policy.
 
 @warning If no SSL pinning policy was configured for the supplied _serverHostname_, this method has no effect and will return `TSKTrustDecisionDomainNotPinned` without validating the supplied _serverTrust_ at all.
 
 Because this will happen in an authentication handler, it means that the server's _serverTrust_ object __needs__ to be verified against the device's trust store using `SecTrustEvaluate()`. Failing to do so will __disable SSL certificate validation__.
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
+ (TSKTrustDecision) evaluateTrust:(SecTrustRef)serverTrust forHostname:(NSString *)serverHostname;

@end
NS_ASSUME_NONNULL_END
