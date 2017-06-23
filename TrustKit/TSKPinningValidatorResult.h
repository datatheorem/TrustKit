/*
 
 TSKPinningValidator.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKTrustDecision.h"
@import Foundation;

/**
 A `TSKPinningValidatorResult` instance contains all the details regarding a pinning validation
 performed against a specific server.
 */
@interface TSKPinningValidatorResult : NSObject

/**
 The hostname of the server SSL pinning validation was performed against.
 */
@property (nonatomic, readonly, nonnull) NSString *serverHostname;

/**
 The original `SecTrustRef` that validation was performed against.
 */
@property (nonatomic, readonly, nonnull) SecTrustRef serverTrust;

/**
 The entry within the SSL pinning configuration that was used as the pinning policy for the
 server being validated. It will be the same as the `serverHostname` unless the server is a 
 subdomain of the domain configured in the pinning policy with `kTSKIncludeSubdomains` enabled. 
 The corresponding pinning configuration that was used for validation can be retrieved using:

     NSDictionary *hostnameConfiguration = [trustKit configuration][kTSKPinnedDomains][notedHostname];
 */
@property (nonatomic, readonly, nonnull) NSString *notedHostname;

/**
 The result of validating the server's certificate chain against the set of SSL pins configured for 
 the `notedHostname`.
 */
@property (nonatomic, readonly) TSKTrustEvaluationResult validationResult;

/**
 The trust decision returned for this connection, which describes whether the connection should be blocked 
 or allowed, based on the `validationResult` returned when evaluating the `serverTrust` and the SSL pining 
 policy configured for this server.

 For example, the pinning validation could have failed (ie. validationResult being 
 `TSKTrustEvaluationFailedNoMatchingPin`) but the policy might be set to ignore pinning validation failures 
 for this server, thereby returning `TSKTrustDecisionShouldAllowConnection`.
 */
@property (nonatomic, readonly) TSKTrustDecision finalTrustDecision;

/**
 The time it took for the SSL pinning validation to be performed.
 */
@property (nonatomic, readonly) NSTimeInterval validationDuration;

/**
 The certificate chain extracted from the `serverTrust` as PEM-formatted certificates. This is the 
 certificate chain sent by the server when establishing the connection.
 */
@property (nonatomic, readonly, nullable) NSArray *certificateChain;

/// :nodoc:
- (instancetype _Nullable)initWithServerHostname:(NSString * _Nonnull)serverHostname
                           serverTrust:(SecTrustRef _Nonnull)serverTrust
                         notedHostname:(NSString * _Nonnull)notedHostname
                      validationResult:(TSKTrustEvaluationResult)validationResult
                    finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                    validationDuration:(NSTimeInterval)validationDuration;

@end
