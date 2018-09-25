/*
 
 TSKPinFailureReport.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "../Pinning/ssl_pin_verifier.h"

#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

@interface TSKPinFailureReport : NSObject

@property (readonly, nonatomic, nonnull) NSString *appBundleId; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *appVersion; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *appPlatform; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *appPlatformVersion; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *appVendorId; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *trustkitVersion; // Not part of the HPKP spec
@property (readonly, nonatomic, nonnull) NSString *notedHostname;
@property (readonly, nonatomic, nonnull) NSString *hostname;
@property (readonly, nonatomic, nonnull) NSNumber *port;
@property (readonly, nonatomic, nonnull) NSDate *dateTime;
@property (readonly, nonatomic) BOOL includeSubdomains;
@property (readonly, nonatomic, nonnull) NSArray *validatedCertificateChain;
@property (readonly, nonatomic, nonnull) NSArray *knownPins;
@property (readonly, nonatomic) TSKTrustEvaluationResult validationResult; // Not part of the HPKP spec
@property (readonly, nonatomic) BOOL enforcePinning; // Not part of the HPKP spec
@property (readonly, nonatomic, nullable) NSDate *knownPinsExpirationDate; // Not part of the HPKP spec


// Init with default bundle ID and current time as the date-time
- (nonnull instancetype) initWithAppBundleId:(nonnull NSString *)appBundleId
                                  appVersion:(nonnull NSString *)appVersion
                                 appPlatform:(nonnull NSString *)appPlatform
                          appPlatformVersion:(nonnull NSString *)appPlatformVersion
                                 appVendorId:(nonnull NSString *)appVendorId
                             trustkitVersion:(nonnull NSString *)trustkitVersion
                                    hostname:(nonnull NSString *)serverHostname
                                        port:(nonnull NSNumber *)serverPort
                                    dateTime:(nonnull NSDate *)dateTime
                               notedHostname:(nonnull NSString *)notedHostname
                           includeSubdomains:(BOOL)includeSubdomains
                              enforcePinning:(BOOL)enforcePinning
                   validatedCertificateChain:(nonnull NSArray<NSString *> *)validatedCertificateChain
                                   knownPins:(nonnull NSArray<NSString *> *)knownPins
                            validationResult:(TSKTrustEvaluationResult)validationResult
                              expirationDate:(nullable NSDate *)knownPinsExpirationDate;

// Return the report in JSON format for POSTing it
- (nonnull NSData *)json;

// Return a request ready to be sent with the report in JSON format in the response's body
- (nonnull NSMutableURLRequest *)requestToUri:(nonnull NSURL *)reportUri;


@end
