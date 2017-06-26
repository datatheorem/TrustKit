//
//  TSKPinningValidator_Private.h
//  TrustKit
//
//  Created by Alban Diquet on 6/23/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

#ifndef TSKPinningValidator_Private_h
#define TSKPinningValidator_Private_h


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
- (instancetype _Nullable)initWithDomainPinningPolicies:(NSDictionary<NSString *, TKSDomainPinningPolicy *> *_Nonnull)domainPinningPolicies
                                              hashCache:(TSKSPKIHashCache * _Nonnull)hashCache
                          ignorePinsForUserTrustAnchors:(BOOL)ignorePinsForUserTrustAnchors
                                validationCallbackQueue:(dispatch_queue_t _Nonnull)validationCallbackQueue
                                     validationCallback:(TSKPinningValidatorCallback _Nonnull)validationCallback;

@end


@interface TSKPinningValidatorResult (Internal)

- (instancetype _Nullable)initWithServerHostname:(NSString * _Nonnull)serverHostname
                                     serverTrust:(SecTrustRef _Nonnull)serverTrust
                                validationResult:(TSKTrustEvaluationResult)validationResult
                              finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                              validationDuration:(NSTimeInterval)validationDuration;

@end


#endif /* TSKPinningValidator_Private_h */

