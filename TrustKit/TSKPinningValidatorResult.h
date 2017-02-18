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

@property (nonatomic, nonnull) NSString *serverHostname;
@property (nonatomic, nonnull) SecTrustRef serverTrust;
@property (nonatomic, nonnull) NSString *notedHostname;
@property (nonatomic) TSKPinValidationResult validationResult;
@property (nonatomic) TSKTrustDecision finalTrustDecision;
@property (nonatomic) NSTimeInterval validationDuration;
@property (nonatomic, readonly, nullable) NSArray *certificateChain;

@end
