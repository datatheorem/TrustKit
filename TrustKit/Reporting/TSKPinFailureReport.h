/*
 
 TSKPinFailureReport.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "ssl_pin_verifier.h"


@interface TSKPinFailureReport : NSObject

@property (readonly, nonatomic) NSString *appBundleId; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *appVersion; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *appPlatform; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *appVendorId; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *trustkitVersion; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *notedHostname;
@property (readonly, nonatomic) NSString *hostname;
@property (readonly, nonatomic) NSNumber *port;
@property (readonly, nonatomic) NSDate *dateTime;
@property (readonly, nonatomic) BOOL includeSubdomains;
@property (readonly, nonatomic) NSArray *validatedCertificateChain;
@property (readonly, nonatomic) NSArray *knownPins;
@property (readonly, nonatomic) TSKPinValidationResult validationResult; // Not part of the HPKP spec
@property (readonly, nonatomic) BOOL enforcePinning; // Not part of the HPKP spec


// Init with default bundle ID and current time as the date-time
- (instancetype) initWithAppBundleId:(NSString *)appBundleId
                          appVersion:(NSString *)appVersion
                         appPlatform:(NSString *)appPlatform
                         appVendorId:(NSString *)appVendorId
                     trustkitVersion:(NSString *)trustkitVersion
                            hostname:(NSString *)serverHostname
                                port:(NSNumber *)serverPort
                            dateTime:(NSDate *)dateTime
                       notedHostname:(NSString *)notedHostname
                   includeSubdomains:(BOOL) includeSubdomains
                      enforcePinning:(BOOL)enforcePinning
           validatedCertificateChain:(NSArray<NSString *> *)validatedCertificateChain
                           knownPins:(NSArray<NSString *> *)knownPins
                    validationResult:(TSKPinValidationResult) validationResult;

// Return the report in JSON format for POSTing it
- (NSData *)json;

// Return a request ready to be sent with the report in JSON format in the response's body
- (NSMutableURLRequest *)requestToUri:(NSURL *)reportUri;


@end
