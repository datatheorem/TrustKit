/*
 
 reporting_utils.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

@import Foundation;

#ifndef TrustKit_reporting_utils_h
#define TrustKit_reporting_utils_h

NSArray<NSString *> *convertTrustToPemArray(SecTrustRef serverTrust);
NSArray<NSString *> *convertPinsToHpkpPins(NSSet<NSData *> *knownPins);

#endif
