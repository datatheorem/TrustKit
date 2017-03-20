/*
 
 TSKPinningValidator.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKPinValidatorResult.h"

@interface TSKPinningValidatorResult : NSObject

/**
 The hostname of the server SSL pinning validation was performed against.
 */
@property (nonatomic, nonnull) NSString *serverHostname;

/**
 The original SecTrustRef that validation was performed against.
 */
@property (nonatomic, nonnull) SecTrustRef serverTrust;

/**
 The entry within the SSL pinning configuration that was used as the pinning policy for the
 server being validated. It will be the same as the `kTSKValidationServerHostnameNotificationKey` 
 entry unless the server is a subdomain of a domain configured in the pinning policy with
 `kTSKIncludeSubdomains` enabled. The corresponding pinning configuration that was used
 for validation can be retrieved using:

     NSString *notedHostname = userInfo[kTSKValidationNotedHostnameNotificationKey];
     NSDictionary *hostnameConfiguration = [TrustKit configuration][kTSKPinnedDomains][notedHostname];
 */
@property (nonatomic, nonnull) NSString *notedHostname;

/**
 The `TSKPinValidationResult` returned when validating the server's certificate chain, which
 represents the result of evaluating the certificate chain against the configured SSL pins 
 for this server.
 */
@property (nonatomic) TSKPinValidationResult validationResult;

/**
 The `TSKTrustDecision` returned when validating the certificate's chain, which describes
 whether the connection should be blocked or allowed, based on the `TSKPinningValidationResult`
 returned when evaluating the server's certificate chain and the SSL pining policy configured 
 for this server.

 For example, the pinning validation could have failed (returning `TSKPinningValidationFailed`)
 but the policy might be set to ignore pinning validation failures for this server, thereby
 returning `TSKTrustDecisionShouldAllowConnection`.
 */
@property (nonatomic) TSKTrustDecision finalTrustDecision;

/**
 The time in seconds it took for the SSL pinning validation to be performed.
 */
@property (nonatomic) NSTimeInterval validationDuration;

/**
 The certificate chain returned by the server as an array of PEM-formatted certificates.
 */
@property (nonatomic, readonly, nullable) NSArray *certificateChain;

@end
