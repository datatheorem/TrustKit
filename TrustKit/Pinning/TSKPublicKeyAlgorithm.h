/*
 
 TSKPublicKeyAlgorithm.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TSKPublicKeyAlgorithm_h
#define TSKPublicKeyAlgorithm_h

@import Foundation;

// The internal enum we use for public key algorithms; not to be confused with the exported TSKSupportedAlgorithm
typedef NS_ENUM(NSInteger, TSKPublicKeyAlgorithm)
{
    // Some assumptions are made about this specific ordering in public_key_utils.m
    TSKPublicKeyAlgorithmRsa2048 = 0,
    TSKPublicKeyAlgorithmRsa4096 = 1,
    TSKPublicKeyAlgorithmEcDsaSecp256r1 = 2,
    TSKPublicKeyAlgorithmEcDsaSecp384r1 = 3,
    
    TSKPublicKeyAlgorithmLast = TSKPublicKeyAlgorithmEcDsaSecp384r1
};

#endif /* TSKPublicKeyAlgorithm_h */
