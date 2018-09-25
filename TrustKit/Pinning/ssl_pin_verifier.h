/*
 
 ssl_pin_verifier.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "../TSKTrustDecision.h"
#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

@class TSKSPKIHashCache;

// Validate that the server trust contains at least one of the know/expected pins
TSKTrustEvaluationResult verifyPublicKeyPin(SecTrustRef _Nonnull serverTrust,
                                            NSString * _Nonnull serverHostname,
                                            NSSet<NSData *> * _Nonnull knownPins,
                                            TSKSPKIHashCache * _Nullable hashCache);
