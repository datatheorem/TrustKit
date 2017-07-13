/*
 
 vendor_identifier.h
 TrustKit
 
 Copyright 2016 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

@import Foundation;

// Will return the IDFV on platforms that support it (iOS, tvOS) and a randomly generated UUID on other platforms (macOS, watchOS)
NSString *identifier_for_vendor(void);
