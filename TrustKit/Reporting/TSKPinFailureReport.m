//
//  TSKPinFailureReport.m
//  TrustKit
//
//  Created by Alban Diquet on 5/27/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import "TSKPinFailureReport.h"

@implementation TSKPinFailureReport


- (instancetype) initWithAppVersion:(NSString *)appVersion notedHostname:(NSString *)notedHostname serverHostname:(NSString *)serverHostname port:(NSNumber *)serverPort includeSubdomains:(BOOL) includeSubdomains validatedCertificateChain:(NSArray *)validatedCertificateChain knownPins:(NSArray *)knownPins;
{
    self = [super init];
    if (self)
    {
        _appBundleId = [[NSBundle mainBundle] bundleIdentifier];
        _appVersion = appVersion;
        _notedHostname = notedHostname;
        _serverHostname = serverHostname;
        _serverPort = serverPort;
        _dateTime = [NSDate date];
        _includeSubdomains = includeSubdomains;
        _validatedCertificateChain = validatedCertificateChain;
        _knownPins = knownPins;
    }
    return self;
}


-(NSData *)json;
{
    // Convert the date to a string
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *currentTimeStr = [dateFormatter stringFromDate: self.dateTime];
    
    // TODO: Convert knownPins and validatedCertificateChain
    
    // Create the dictionary
    NSDictionary *requestData = [[NSDictionary alloc] initWithObjectsAndKeys:
                                 self.appBundleId, @"app-bundle-id",
                                 self.appVersion, @"app-version",
                                 currentTimeStr, @"date-time",
                                 self.serverHostname, @"hostname",
                                 [self.serverPort stringValue], @"port",
                                 [NSNumber numberWithBool:self.includeSubdomains], @"include-subdomains",
                                 self.notedHostname, @"noted-hostname",
                                 self.validatedCertificateChain, @"validated-certificate-chain",
                                 self.knownPins, @"known-pins",
                                 nil];
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&error];
    return jsonData;
}

@end
