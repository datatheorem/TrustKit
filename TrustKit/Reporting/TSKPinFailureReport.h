//
//  TSKPinFailureReport.h
//  TrustKit
//
//  Created by Alban Diquet on 5/27/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TSKPinFailureReport : NSObject

@property (readonly, nonatomic) NSString *appBundleId; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *appVersion; // Not part of the HPKP spec
@property (readonly, nonatomic) NSString *notedHostname;
@property (readonly, nonatomic) NSString *hostname;
@property (readonly, nonatomic) NSNumber *port;
@property (readonly, nonatomic) NSDate *dateTime;
@property (readonly, nonatomic) BOOL includeSubdomains;
@property (readonly, nonatomic) NSArray *validatedCertificateChain;
@property (readonly, nonatomic) NSArray *knownPins;


// Init with default bundle ID and current time as the date-time
- (instancetype) initWithAppBundleId:(NSString *) appBundleId appVersion:(NSString *)appVersion notedHostname:(NSString *)notedHostname hostname:(NSString *)serverHostname port:(NSNumber *)serverPort dateTime:(NSDate *)dateTime includeSubdomains:(BOOL) includeSubdomains validatedCertificateChain:(NSArray *)validatedCertificateChain knownPins:(NSArray *)knownPins;

// Return the report in JSON format for POSTing it
- (NSData *)json;

// Return a request ready to be sent with the report in JSON format in the response's body
- (NSMutableURLRequest *)requestToUri:(NSURL *)reportUri;


@end
