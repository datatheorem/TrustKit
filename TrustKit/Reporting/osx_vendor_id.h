/*
 
 osx_vendor_id.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef osx_vendor_id_h
#define osx_vendor_id_h

#import <Foundation/Foundation.h>

// Because OS X does not provide an IDFV, we generate have to generate one ourselves
// We use the SHA1 hash of the device's MAC address and the App's bundle ID
NSString *osx_identifier_for_vendor(NSString *bundleId);

#endif /* osx_vendor_id_h */
