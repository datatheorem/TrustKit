/*
 
 public_key_utils.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TrustKit_subjectPublicKeyHash_h
#define TrustKit_subjectPublicKeyHash_h

#import <Foundation/Foundation.h>
@import Security;


typedef NS_ENUM(NSInteger, TSKPublicKeyAlgorithm)
{
    TSKPublicKeyAlgorithmRsa2048 = 0,
    TSKPublicKeyAlgorithmRsa4096 = 1,
    TSKPublicKeyAlgorithmEcDsaSecp256r1 = 2,
};


void initializeSubjectPublicKeyInfoCache(void);

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm);


// For tests
void resetSubjectPublicKeyInfoCache(void);
NSMutableDictionary *getSpkiCacheFromFileSystem(void);

#endif
