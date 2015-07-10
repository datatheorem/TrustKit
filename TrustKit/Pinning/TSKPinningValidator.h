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
typedef NS_ENUM(NSInteger, TSKPinValidationResult)
{
/**
 The server trust was succesfully evaluated and contained at least one of the configured pins.
*/
    TSKPinValidationResultSuccess,
    
/**
 The server trust was succesfully evaluated but did not contain any of the configured pins.
*/
    TSKPinValidationResultFailed,
    
/**
 The server trust's evaluation failed: the server's certificate chain is not trusted.
*/
    TSKPinValidationResultFailedCertificateChainNotTrusted,
    
/**
 The server trust could not be evaluated due to invalid parameters.
*/
    TSKPinValidationResultErrorInvalidParameters,
    
/**
 The supplied hostname does not have a pinning policy configured; no validation was performed.
*/
    TSKPinValidationResultDomainNotPinned,
    
/**
 The server trust was succesfully evaluated but did not contain any of the configured pins. However, the certificate chain terminates at a user-defined trust anchor (ie. a custom/private CA that was manually added to OS X's trust store). Only available on OS X.
*/
    TSKPinValidationResultFailedUserDefinedTrustAnchor NS_AVAILABLE_MAC(10_9),
};


/**
 `TSKPinningValidator` is a class for manually verifying a server's identity against the global SSL pinning policy.
 
 In a few specific scenarios, TrustKit cannot intercept outgoing SSL connections and automatically validate the server's identity against the pinning policy. For these connections, the pin validation must be manually triggered: the server's trust object, which contains its certificate chain, needs to be retrieved or built before being passed to `TSKPinningValidator` for validation.
 
 The following scenarios require manual pin validation:
 
 1. Connections initiated from an external process, where TrustKit does not get loaded:
     * `WKWebView` connections: the server's trust object can be retrieved within the `webView:didReceiveAuthenticationChallenge:completionHandler:` method.
     * `NSURLSession` connections using the background transfer service: the server's trust object can be retrieved within the `application:handleEventsForBackgroundURLSession:completionHandler:` method.
 2. Connections initiated using a third-party SSL library such as OpenSSL, instead of Apple's SecureTransport. The server's trust object needs to be built using the received certificate chain.
 
 */
@interface TSKPinningValidator : NSObject

///------------------------------------
/// @name Manual SSL Pinning Validation
///------------------------------------

/**
 Evaluate the supplied server trust against the global SSL pinning policy previously configured. If the validation fails, pin failure reports will be sent according to the pinning policy.
 
 @param serverTrust The trust object representing the server's certificate chain. The trust's evaluation policy is always overridden using `SecTrustSetPolicies()` to ensure all the proper SSL checks (expiration, hostname validation, etc.) are enabled.
 
 @param serverHostname The hostname of the server whose identity is being validated.
 
 @return The result of the validation. See `TSKPinValidationResult` for possible values.
 
 @warning If no SSL pinning policy was configured for the supplied _serverHostname_, this method has no effect and will return `TSKPinValidationResultDomainNotPinned` without validating the supplied _serverTrust_ at all.
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
+ (TSKPinValidationResult) evaluateTrust:(SecTrustRef)serverTrust forHostname:(NSString *)serverHostname;

@end
