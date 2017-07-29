/*
 
 TSKPinningValidator.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinningValidatorResult.h"
#import "Reporting/reporting_utils.h"

@implementation TSKPinningValidatorResult

- (instancetype _Nullable)initWithServerHostname:(NSString * _Nonnull)serverHostname
                                     serverTrust:(SecTrustRef _Nonnull)serverTrust
                                validationResult:(TSKTrustEvaluationResult)validationResult
                              finalTrustDecision:(TSKTrustDecision)finalTrustDecision
                              validationDuration:(NSTimeInterval)validationDuration
{
    NSParameterAssert(serverHostname);
    NSParameterAssert(serverTrust);
    
    self = [super init];
    if (self) {
        _serverHostname = serverHostname;
        _evaluationResult = validationResult;
        _finalTrustDecision = finalTrustDecision;
        _validationDuration = validationDuration;
        
        // Convert the server trust to a certificate chain as soon as we get it, as the trust object sometimes gets freed right after the authentication challenge has been handled
        _certificateChain = convertTrustToPemArray(serverTrust);
    }
    return self;
}

@end
