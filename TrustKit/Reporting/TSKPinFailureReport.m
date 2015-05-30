//
//  TSKPinFailureReport.m
//  TrustKit
//
//  Created by Alban Diquet on 5/27/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TSKPinFailureReport.h"

@implementation TSKPinFailureReport


- (instancetype) initWithAppBundleId:(NSString *) appBundleId
                          appVersion:(NSString *)appVersion
                       notedHostname:(NSString *)notedHostname
                            hostname:(NSString *)serverHostname
                                port:(NSNumber *)serverPort
                            dateTime:(NSDate *)dateTime
                   includeSubdomains:(BOOL) includeSubdomains
           validatedCertificateChain:(NSArray *)validatedCertificateChain
                           knownPins:(NSArray *)knownPins
{
    self = [super init];
    if (self)
    {
        _appBundleId = appBundleId;
        _appVersion = appVersion;
        _notedHostname = notedHostname;
        _hostname = serverHostname;
        _port = serverPort;
        _dateTime = dateTime;
        _includeSubdomains = includeSubdomains;
        _validatedCertificateChain = validatedCertificateChain;
        _knownPins = knownPins;
    }
    return self;
}


- (NSData *)json;
{
    // Convert the date to a string
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *currentTimeStr = [dateFormatter stringFromDate: self.dateTime];
    
    // TODO: Convert knownPins and validatedCertificateChain
    
    // Create the dictionary
    NSDictionary *requestData = @ {
        @"app-bundle-id" : self.appBundleId,
        @"app-version" : self.appVersion,
        @"date-time" : currentTimeStr,
        @"hostname" : self.hostname,
        @"port" : self.port,
        @"include-subdomains" : [NSNumber numberWithBool:self.includeSubdomains],
        @"noted-hostname" : self.notedHostname,
        @"validated-certificate-chain" : self.validatedCertificateChain,
        @"known-pins" : self.knownPins
    };
    
    // TODO: Check error
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&error];
    return jsonData;
}


- (NSMutableURLRequest *)requestToUri:(NSURL *)reportUri
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportUri];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:[self json]];
    return request;
}


@end
