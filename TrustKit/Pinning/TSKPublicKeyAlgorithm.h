/*
 
 TSKPublicKeyAlgorithm.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TSKPublicKeyAlgorithm_h
#define TSKPublicKeyAlgorithm_h

#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

// The internal enum we use for public key algorithms; not to be confused with the exported TSKSupportedAlgorithm
typedef NS_ENUM(NSInteger, TSKPublicKeyAlgorithm)
{
    // Some assumptions are made about this specific ordering in public_key_utils.m
    TSKPublicKeyAlgorithmRsa2048 = 0,
    TSKPublicKeyAlgorithmRsa4096 = 1,
    TSKPublicKeyAlgorithmEcDsaSecp256r1 = 2,
    TSKPublicKeyAlgorithmEcDsaSecp384r1 = 3,
    
    TSKPublicKeyAlgorithmLast = TSKPublicKeyAlgorithmEcDsaSecp384r1
} __deprecated_msg("Starting with TrustKit 1.6.0, key algorithms no longer need to be specified; remove TSKPublicKeyAlgorithms from your configuration.");

#endif /* TSKPublicKeyAlgorithm_h */
