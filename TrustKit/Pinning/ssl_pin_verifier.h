/*
 
 ssl_pin_verifier.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */


#import <Foundation/Foundation.h>


/**
 Possible return values when verifying a server's identity. 
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
    TSKPinValidationResultFailedCertificateChainNotTrusted,
    
    /**
     The server trust could not be evaluated due to invalid parameters.
     */
    TSKPinValidationResultErrorInvalidParameters,

    /**
     The server trust was succesfully evaluated but did not contain any of the configured pins. However, the certificate chain terminates at a user-defined trust anchor (ie. a custom/private CA that was manually added to OS X's trust store). Only available on OS X.
     */
    TSKPinValidationResultFailedUserDefinedTrustAnchor NS_AVAILABLE_MAC(10_9),
    
    /**
     The server trust could not be evaluated due to an error when trying to generate the certificate's subject public key info hash. On iOS, this could be caused by a Keychain failure when trying to extract the certificate's public key bytes.
     */
    TSKPinValidationResultErrorCouldNotGenerateSpkiHash,
};


// Figure out if a specific domain is pinned and retrieve this domain's configuration key; returns nil if no configuration was found
NSString *getPinningConfigurationKeyForDomain(NSString *hostname, NSDictionary *trustKitConfiguration);

// Validate that the server trust contains at least one of the know/expected pins
TSKPinValidationResult verifyPublicKeyPin(SecTrustRef serverTrust, NSString *serverHostname, NSArray<NSNumber *> *supportedAlgorithms, NSSet<NSData *> *knownPins);

