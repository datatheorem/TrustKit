/*
 
 TSKPinningValidator.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKPinValidatorResult.h"
#import "Pinning/TSKPublicKeyAlgorithm.h"

@class TSKPinningValidatorResult;

typedef NSData* _Nullable(^HashCertificateBlock)(_Nonnull SecCertificateRef certificate, TSKPublicKeyAlgorithm algorithm);

/**
 `TSKPinningValidator` is a class for manually verifying a server's identity against the global SSL pinning policy.
 
 In specific scenarios, TrustKit cannot intercept outgoing SSL connections and automatically validate the server's identity against the pinning policy:
 
 * All connections within an App that disables TrustKit's network delegate swizzling by setting the `kTSKSwizzleNetworkDelegates` configuration key to `NO`.
 * Connections that do not rely on the `NSURLConnection` or `NSURLSession` APIs:
     * `WKWebView` connections.
     * Connections leveraging low-level network APIs (such as `NSStream`).
     * Connections initiated using a third-party SSL library such as OpenSSL.
 
 For these connections, pin validation must be manually triggered using one of the two available methods:
 
 * `evaluateTrust:forHostname:` which evaluates the server's certificate chain against the global SSL pinning policy.
 * `handleChallenge:completionHandler:` a helper method to be used for implementing pinning validation in challenge handler methods within `NSURLSession` and `WKWebView` delegates.
 
 */

@interface TSKPinningValidator : NSObject

///------------------------------------
/// @name Manual SSL Pinning Validation
///------------------------------------

@property (nonatomic, readonly, nullable) NSDictionary *pinnedDomains;
@property (nonatomic, readonly) BOOL ignorePinsForUserTrustAnchors;
@property (nonatomic, readonly, nonnull) dispatch_queue_t validationResultQueue;
@property (nonatomic, readonly, nonnull) void(^validationResultHandler)(TSKPinningValidatorResult * _Nonnull result);

- (instancetype _Nullable)initWithPinnedDomainConfig:(NSDictionary * _Nullable)pinnedDomains
                       ignorePinsForUserTrustAnchors:(BOOL)ignorePinsForUserTrustAnchors
                               validationResultQueue:(dispatch_queue_t _Nonnull)validationResultQueue
                             validationResultHandler:(void(^ _Nonnull)(TSKPinningValidatorResult * _Nonnull result))validationResultHandler;

/**
 Evaluate the supplied server trust against the global SSL pinning policy previously configured. If the validation fails, a pin failure report will be sent.
 
 When using the `NSURLSession` or `WKWebView` network APIs, the `handleChallenge:completionHandler:` method should be called instead, as it is simpler to use.
 
 When using low-level network APIs (such as `NSStream`), instructions on how to retrieve the connection's `serverTrust` are available at https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html .
 
 @param serverTrust The trust object representing the server's certificate chain. The trust's evaluation policy is always overridden using `SecTrustSetPolicies()` to ensure all the proper SSL checks (expiration, hostname validation, etc.) are enabled.
 
 @param serverHostname The hostname of the server whose identity is being validated.
 
 @return A `TSKTrustDecision` which describes whether the SSL connection should be allowed or blocked, based on the global pinning policy.
 
 @warning If no SSL pinning policy was configured for the supplied _serverHostname_, this method has no effect and will return `TSKTrustDecisionDomainNotPinned` without validating the supplied _serverTrust_ at all. This means that the server's _serverTrust_ object __must__ be verified against the device's trust store using `SecTrustEvaluate()`. Failing to do so will __disable SSL certificate validation__.
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
- (TSKTrustDecision) evaluateTrust:(SecTrustRef _Nonnull)serverTrust forHostname:(NSString * _Nonnull)serverHostname;


/**
 Helper method for handling authentication challenges received within a `NSURLSessionDelegate`, `NSURLSessionTaskDelegate` or `WKNavigationDelegate`.
 
 This method will evaluate the server trust within the authentication challenge against the global SSL pinning policy previously configured, and then call the `completionHandler` with the corresponding `disposition` and `credential`. For example, this method can be leveraged in a `WKNavigationDelegate` challenge handler method:

    - (void)webView:(WKWebView *)webView
    didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
                                NSURLCredential *credential))completionHandler
    {
        if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
        {
            [TSKPinningValidator handleChallenge:challenge completionHandler:completionHandler];
        }
    }
 
 @param challenge The authentication challenge, supplied by the URL loading system to the delegate's challenge handler method.
 
 @param completionHandler A block to invoke to respond to the challenge, supplied by the URL loading system to the delegate's challenge handler method.
 
 @return `YES` if the challenge was handled and the `completionHandler` was successfuly invoked. `NO` if the challenge could not be handled because it was not for server certificate validation (ie. the challenge's `authenticationMethod` was not `NSURLAuthenticationMethodServerTrust`).
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
- (BOOL) handleChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
       completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                            NSURLCredential * _Nullable credential))completionHandler;

@end

#pragma mark Global Singleton-Based Methods Category

@interface TSKPinningValidator (GlobalTrustKit)

/**
 Evaluate the supplied server trust against the global SSL pinning policy previously configured. If the validation fails, a pin failure report will be sent.
 
 When using the `NSURLSession` or `WKWebView` network APIs, the `handleChallenge:completionHandler:` method should be called instead, as it is simpler to use.
 
 When using low-level network APIs (such as `NSStream`), instructions on how to retrieve the connection's `serverTrust` are available at https://developer.apple.com/library/mac/documentation/NetworkingInternet/Conceptual/NetworkingTopics/Articles/OverridingSSLChainValidationCorrectly.html .
 
 @param serverTrust The trust object representing the server's certificate chain. The trust's evaluation policy is always overridden using `SecTrustSetPolicies()` to ensure all the proper SSL checks (expiration, hostname validation, etc.) are enabled.
 
 @param serverHostname The hostname of the server whose identity is being validated.
 
 @return A `TSKTrustDecision` which describes whether the SSL connection should be allowed or blocked, based on the global pinning policy.
 
 @warning If no SSL pinning policy was configured for the supplied _serverHostname_, this method has no effect and will return `TSKTrustDecisionDomainNotPinned` without validating the supplied _serverTrust_ at all. This means that the server's _serverTrust_ object __must__ be verified against the device's trust store using `SecTrustEvaluate()`. Failing to do so will __disable SSL certificate validation__.
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
+ (TSKTrustDecision) evaluateTrust:(SecTrustRef _Nonnull)serverTrust forHostname:(NSString * _Nonnull)serverHostname;


/**
 Helper method for handling authentication challenges received within a `NSURLSessionDelegate`, `NSURLSessionTaskDelegate` or `WKNavigationDelegate`.
 
 This method will evaluate the server trust within the authentication challenge against the global SSL pinning policy previously configured, and then call the `completionHandler` with the corresponding `disposition` and `credential`. For example, this method can be leveraged in a `WKNavigationDelegate` challenge handler method:
     
     - (void)webView:(WKWebView *)webView
     didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
     completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
     NSURLCredential *credential))completionHandler
     {
         if (![TSKPinningValidator handleChallenge:challenge completionHandler:completionHandler]) 
         {
             // TrustKit did not handle this challenge: perhaps it was not for server trust
             // or the domain was not pinned. Fall back to the default behavior
             completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
         }
     }
 
 @param challenge The authentication challenge, supplied by the URL loading system to the delegate's challenge handler method.
 
 @param completionHandler A block to invoke to respond to the challenge, supplied by the URL loading system to the delegate's challenge handler method.
 
 @return `YES` if the challenge was handled and the `completionHandler` was successfuly invoked. `NO` if the challenge could not be handled because it was not for server certificate validation (ie. the challenge's `authenticationMethod` was not `NSURLAuthenticationMethodServerTrust`).
 
 @exception NSException Thrown when TrustKit has not been initialized with a pinning policy.
 */
+ (BOOL) handleChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
       completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                            NSURLCredential * _Nullable credential))completionHandler;
@end
