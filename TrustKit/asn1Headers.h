//
//  asn1Headers.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//


#ifndef __TrustKit__asn1Headers__
#define __TrustKit__asn1Headers__

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, TSKPublicKeyAlgorithm)
{
    TSKPublicKeyAlgorithmRsa2048 = 0,
    TSKPublicKeyAlgorithmRsa4096 = 1,
    TSKPublicKeyAlgorithmEcDsaSecp256r1 = 2,
};


const unsigned char *getAsn1HeaderBytesForPublicKeyAlgorithm(TSKPublicKeyAlgorithm alg);
unsigned int getAsn1HeaderSizeForPublicKeyAlgorithm(TSKPublicKeyAlgorithm alg);


#endif /* defined(__TrustKit__asn1Headers__) */
