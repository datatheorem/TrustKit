/*
 
 TSKPinningValidator_Private.h
 TrustKit
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

NS_ASSUME_NONNULL_BEGIN

/* Methods that are internal to TrustKit */
@interface TSKPinningValidator (Internal)

/**
 Initialize an instance of TSKPinningValidator.
 
 @param domainPinningPolicies A dictionnary of domains and the corresponding pinning policy.
 @param hashCache The hash cache to use. If nil, no caching is performed, performance may suffer.
 @param ignorePinsForUserTrustAnchors Set to true to ignore the trust anchors in the user trust store
 @param validationCallbackQueue The queue used when invoking the validationResultHandler
 @param validationCallback The callback invoked with validation results
 @return Initialized instance
 */
- (instancetype _Nullable)initWithDomainPinningPolicies:(NSDictionary<NSString *, TKSDomainPinningPolicy *> *)domainPinningPolicies
                                              hashCache:(TSKSPKIHashCache *)hashCache
                          ignorePinsForUserTrustAnchors:(BOOL)ignorePinsForUserTrustAnchors
                                validationCallbackQueue:(dispatch_queue_t)validationCallbackQueue
                                     validationCallback:(TSKPinningValidatorCallback)validationCallback;

@end


@interface TSKPinningValidatorResult (Internal)

- (instancetype _Nullable)initWithServerHostname:(NSString *)serverHostname
                                     serverTrust:(SecTrustRef)serverTrust
                                validationResult:(TSKTrustEvaluationResult)validationResult
                              finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                              validationDuration:(NSTimeInterval)validationDuration;

@end

NS_ASSUME_NONNULL_END
