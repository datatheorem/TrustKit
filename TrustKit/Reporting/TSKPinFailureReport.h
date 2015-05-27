//
//  TSKPinFailureReport.h
//  TrustKit
//
//  Created by Alban Diquet on 5/27/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TSKPinFailureReport : NSObject

@property NSString *appBundleId;
@property NSString *appVersion;
@property NSString *notedHostname;
@property NSString *serverHostname;
@property NSNumber *serverPort;
@property NSDate *dateTime;
@property BOOL includeSubdomains;
@property NSArray *validatedCertificateChain;
@property NSArray *knownPins;

// Init with default bundle ID and current time as the date-time
- (instancetype) initWithAppVersion:(NSString *)appVersion notedHostname:(NSString *)notedHostname serverHostname:(NSString *)serverHostname port:(NSNumber *)serverPort includeSubdomains:(BOOL) includeSubdomains validatedCertificateChain:(NSArray *)validatedCertificateChain knownPins:(NSArray *)knownPins;

// Return the report in JSON format for POSTing it
-(NSData *)json;

@end
