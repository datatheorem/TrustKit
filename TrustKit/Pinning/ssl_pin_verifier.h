//
//  ssl_pin_verifier.h
//  TrustKit
//
//  Created by Alban Diquet on 4/23/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_ssl_pin_verifier_h
#define TrustKit_ssl_pin_verifier_h

#import <Foundation/Foundation.h>
#import "TSKPinVerifier.h"


// Figure out if a specific domain is pinned and retrieve this domain's configuration; returns nil if no configuration was found
NSDictionary *getPinningConfigurationForDomain(NSString *hostname, NSDictionary *trustKitConfiguration);

// Validate that the server trust contains at least one of the know/expected pins
TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSArray *supportedAlgorithms, NSSet *knownPins);


#endif
