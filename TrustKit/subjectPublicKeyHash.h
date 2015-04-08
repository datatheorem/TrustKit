//
//  subjectPublicKeyHash.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_subjectPublicKeyHash_h
#define TrustKit_subjectPublicKeyHash_h

#import "asn1Headers.h"
@import Security;


void initializeSubjectPublicKeyInfoCache(void);
void resetSubjectPublicKeyInfoCache(void);

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate, TSKPublicKeyAlgorithm publicKeyAlgorithm);

#endif
