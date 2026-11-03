/*

 vendor_identifier.h
 TrustKit

 Copyright 2016 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

// Not the IDFV: a random UUID generated once per install and stored in the App's user defaults, on every platform
NSString *identifier_for_vendor(void);
