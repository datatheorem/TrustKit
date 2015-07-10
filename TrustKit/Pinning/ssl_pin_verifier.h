/*
 
 ssl_pin_verifier.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */


#ifndef TrustKit_ssl_pin_verifier_h
#define TrustKit_ssl_pin_verifier_h

#import <Foundation/Foundation.h>
#import "TSKPinningValidator.h"


// Figure out if a specific domain is pinned and retrieve this domain's configuration key; returns nil if no configuration was found
NSString *getPinningConfigurationKeyForDomain(NSString *hostname, NSDictionary *trustKitConfiguration);

// Validate that the server trust contains at least one of the know/expected pins
TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverHostname, NSArray *supportedAlgorithms, NSSet *knownPins);


#endif
