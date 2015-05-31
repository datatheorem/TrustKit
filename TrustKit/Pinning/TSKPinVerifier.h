//
//  TSKPinVerifier.h
//  TrustKit
//
//  Created by Alban Diquet on 5/25/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>


// Pin validation result values
typedef NS_ENUM(NSInteger, TSKPinValidationResult) {
    TSKPinValidationResultSuccess,
    TSKPinValidationResultFailed,
    TSKPinValidationResultFailedInvalidCertificateChain, // The server's supplied certificate chain is not trusted
    TSKPinValidationResultFailedInvalidParameters,
};


@interface TSKPinVerifier : NSObject

+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andHostname:(NSString *)serverHostname;

@end
