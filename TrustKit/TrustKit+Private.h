//
//  TrustKit+Private.h
//  TrustKit
//
//  Created by Eric on 30/03/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_TrustKit_Private____FILEEXTENSION___
#define TrustKit_TrustKit_Private____FILEEXTENSION___

typedef NS_ENUM(NSInteger, TSKPinValidationResult) {
    TSKPinValidationResultSuccess,
    TSKPinValidationResultFailed,
    TSKPinValidationResultDomainNotPinned,
    TSKPinValidationResultInvalidParameters,
    TSKPinValidationResultPinningDisabled
};

TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverName, NSDictionary *TrustKitConfiguration);
NSDictionary *parseTrustKitArguments(NSDictionary *TrustKitArguments);



@interface TrustKit(Private)

+ (void) resetConfiguration;

@end


#endif
