//
//  subjectPublicKeyInfoAsn1Headers.h
//  TrustKit
//
//  Created by Alban Diquet on 4/7/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef __TrustKit__subjectPublicKeyInfoAsn1Headers__
#define __TrustKit__subjectPublicKeyInfoAsn1Headers__

const unsigned char *getAsn1HeaderBytesForPublicKeyType(int type);
unsigned int getAsn1HeaderSizeForPublicKeyType(int type);


#endif /* defined(__TrustKit__subjectPublicKeyInfoAsn1Headers__) */
