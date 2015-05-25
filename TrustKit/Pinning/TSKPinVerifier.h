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
    TSKPinValidationResultDomainNotPinned,
    TSKPinValidationResultInvalidParameters,
    TSKPinValidationResultPinningNotEnforced,
    TSKPinValidationResultInvalidCertificateChain,
};


@interface TSKPinVerifier : NSObject

+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andDomain:(NSString *)serverHostname;

@end
