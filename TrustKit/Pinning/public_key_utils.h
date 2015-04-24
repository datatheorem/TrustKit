//
//  public_key_utils.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

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
void resetSubjectPublicKeyInfoCache(void);

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm);

#endif
