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
    // Some assumptions are made about this specific ordering in public_key_utils.m
    TSKPublicKeyAlgorithmRsa2048 = 0,
    TSKPublicKeyAlgorithmRsa4096 = 1,
    TSKPublicKeyAlgorithmEcDsaSecp256r1 = 2,
    TSKPublicKeyAlgorithmEcDsaSecp384r1 = 3,
    
    TSKPublicKeyAlgorithmLast = TSKPublicKeyAlgorithmEcDsaSecp384r1
};


void initializeSubjectPublicKeyInfoCache(void);

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm);


// For tests
void resetSubjectPublicKeyInfoCache(void);

// Each key is a raw certificate data (for easy lookup) and each value is the certificate's raw SPKI data
typedef NSMutableDictionary<NSData *, NSData *> SpkiCacheDictionnary;

NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *getSpkiCache(void);
NSMutableDictionary<NSNumber *, SpkiCacheDictionnary *> *getSpkiCacheFromFileSystem(void);


#endif
