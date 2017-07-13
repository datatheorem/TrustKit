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

@synthesize certificateChain = _certificateChain;

- (NSArray * _Nullable)certificateChain
{
    if (!_certificateChain) {
        // Convert the server trust to a certificate chain
        // This cannot be done in the dispatch_async() block as sometimes the serverTrust seems to become invalid once the block gets scheduled, even tho its retain count is still positive
        _certificateChain = convertTrustToPemArray(self.serverTrust);
    }
    return _certificateChain;
}

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
        _serverTrust = serverTrust;
        _evaluationResult = validationResult;
        _finalTrustDecision = finalTrustDecision;
        _validationDuration = validationDuration;
    }
    return self;
}

@end
