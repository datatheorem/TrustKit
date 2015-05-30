//
//  reporting_utils.h
//  TrustKit
//
//  Created by Alban Diquet on 5/29/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_reporting_utils_h
#define TrustKit_reporting_utils_h


NSArray *convertTrustToPemArray(SecTrustRef serverTrust);
NSArray *convertPinsToHpkpPins(NSArray *knownPins);

#endif
