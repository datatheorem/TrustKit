//
//  subjectPublicKeyHash.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_subjectPublicKeyHash_h
#define TrustKit_subjectPublicKeyHash_h

@import Security;

//TODO: rename this function
void initializeKeychain(void);
void resetKeychain(void);

NSData *hashSubjectPublicKeyInfoFromCertificate(SecCertificateRef certificate);

#endif
