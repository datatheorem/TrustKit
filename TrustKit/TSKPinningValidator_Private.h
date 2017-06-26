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
 
 @param pinnedDomains Domain pinning configuration, typically obtained by parseTrustKitConfiguration()
 @param hashCache The hash cache to use. If nil, no caching is performed, performance may suffer.
 @param ignorePinsForUserTrustAnchors Set to true to ignore the trust anchors in the user trust store
 @param validationResultQueue The queue used when invoking the validationResultHandler
 @param validationResultHandler The callback invoked with validation results
 @return Initialized instance
 */
- (instancetype _Nullable)initWithPinnedDomainConfig:(NSDictionary * _Nullable)pinnedDomains
                                           hashCache:(TSKSPKIHashCache * _Nonnull)hashCache
                       ignorePinsForUserTrustAnchors:(BOOL)ignorePinsForUserTrustAnchors
                               validationResultQueue:(dispatch_queue_t _Nonnull)validationResultQueue
                             validationResultHandler:(void(^ _Nonnull)(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy))validationResultHandler;

@end



@interface TSKPinningValidatorResult (Internal)

- (instancetype _Nullable)initWithServerHostname:(NSString * _Nonnull)serverHostname
                                     serverTrust:(SecTrustRef _Nonnull)serverTrust
                                validationResult:(TSKTrustEvaluationResult)validationResult
                              finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                              validationDuration:(NSTimeInterval)validationDuration;

@end


#endif /* TSKPinningValidator_Private_h */

