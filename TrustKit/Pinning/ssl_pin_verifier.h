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


TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverName, NSDictionary *TrustKitConfiguration);


#endif
