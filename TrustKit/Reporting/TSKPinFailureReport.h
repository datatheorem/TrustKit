//
//  TSKPinFailureReport.h
//  TrustKit
//
//  Created by Alban Diquet on 5/27/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TSKPinFailureReport : NSObject

@property (readonly) NSString *appBundleId;
@property (readonly) NSString *appVersion;
@property (readonly) NSString *notedHostname;
@property (readonly) NSString *serverHostname;
@property (readonly) NSNumber *serverPort;
@property (readonly) NSDate *dateTime;
@property (readonly) BOOL includeSubdomains;
@property (readonly) NSArray *validatedCertificateChain;
@property (readonly) NSArray *knownPins;


// Init with default bundle ID and current time as the date-time
- (instancetype) initWithAppVersion:(NSString *)appVersion notedHostname:(NSString *)notedHostname serverHostname:(NSString *)serverHostname port:(NSNumber *)serverPort includeSubdomains:(BOOL) includeSubdomains validatedCertificateChain:(NSArray *)validatedCertificateChain knownPins:(NSArray *)knownPins;

// Return the report in JSON format for POSTing it
- (NSData *)json;

// Return a request ready to be sent with the report in JSON format in the response's body
- (NSMutableURLRequest *)requestToUri:(NSURL *)reportUri;


@end
