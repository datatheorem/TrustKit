//
//  TSKPinVerifier.h
//  TrustKit
//
//  Created by Alban Diquet on 5/25/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 Possible return values when verifying a server's identity against the global SSL pinning policy using `TSKPinVerifier`.

 */
typedef NS_ENUM(NSInteger, TSKPinValidationResult)
{
  /**
   The server trust was succesfully evaluated and contained at least one of the configured pins.
  */
    TSKPinValidationResultSuccess,
    
 /**
  The server trust was succesfully evaluated but did not contain any of the configured pins.
 */
    TSKPinValidationResultFailed,
    
 /**
  The server trust's evaluation failed: the server's certificate chain is not trusted.
  */
    TSKPinValidationResultFailedInvalidCertificateChain,
    
 /**
  The server trust could not be evaluated due to invalid parameters.
 */
    TSKPinValidationResultFailedInvalidParameters,
};


/**
 `TSKPinVerifier` is a class for manually verifying a server's identity against the global SSL pinning policy.
 
 This method should only be used to validate certificate chains for SSL connections that are not automatically handled by TrustKit:
 
 * Background upload/download URL sessions, because they are performed in a different process where TrustKit doesn't get loaded.
 * Connections that don't rely on Apple's SecureTransport for SSL and use a third-party library instead (such as OpenSSL).
 
 */
@interface TSKPinVerifier : NSObject

///--------------------------------
/// @name Manual SSL Pin Validation
///--------------------------------

/**
 Verify the validity of the supplied server trust against the global SSL pinning policy previously configured.
 
 @param serverTrust The trust object representing the server's certificate chain. The trust's validation policy is always overriden to ensure all the proper SSL policies (expiration, hostname validation, etc.) are enabled.
 
 @param serverHostname The hostname of the server whose identity is being validated.
 
 @return The result of validation. See `TSKPinValidationResult` for possible values.
 
 @warning If no SSL pinning policy was configured for the supplied _serverHostname_, this method has no effect and will return `TSKPinValidationResultSuccess` without validating the supplied _serverTrust_ at all.
 */
+ (TSKPinValidationResult) verifyPinForTrust:(SecTrustRef)serverTrust andHostname:(NSString *)serverHostname;

@end
