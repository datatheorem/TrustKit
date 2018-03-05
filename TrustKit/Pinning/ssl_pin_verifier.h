/*
 
 ssl_pin_verifier.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKTrustDecision.h"
@import Foundation;

@class TSKSPKIHashCache;

// Validate that the server trust contains at least one of the know/expected pins
TSKTrustEvaluationResult verifyPublicKeyPin(SecTrustRef _Nonnull serverTrust,
                                            NSString * _Nonnull serverHostname,
                                            NSArray<NSNumber *> * _Nonnull supportedAlgorithms,
                                            NSSet<NSData *> * _Nonnull knownPins,
                                            TSKSPKIHashCache * _Nullable hashCache);
