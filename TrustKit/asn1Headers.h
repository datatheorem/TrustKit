//
//  subjectPublicKeyInfoAsn1Headers.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//


#ifndef __TrustKit__subjectPublicKeyInfoAsn1Headers__
#define __TrustKit__subjectPublicKeyInfoAsn1Headers__

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, TSKPublicKeyAlgorithm)
{
    TSKAlgorithmRsa2048,
    TSKAlgorithmRsa4096,
    TSKAlgorithmEcDsaSecp256r1,
};


const unsigned char *getAsn1HeaderForPublicKeyAlgorithm(TSKPublicKeyAlgorithm alg);
unsigned int getAsn1HeaderSizeForPublicKeyAlgorithm(TSKPublicKeyAlgorithm alg);


#endif /* defined(__TrustKit__subjectPublicKeyInfoAsn1Headers__) */
