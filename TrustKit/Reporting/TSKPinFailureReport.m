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
        if (_appBundleId == nil)
        {
            // Happens in unit tests
            _appBundleId = @"N/A";
        }
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
    NSDictionary *requestData = @ {
        @"app-bundle-id" : self.appBundleId,
        @"app-version" : self.appVersion,
        @"date-time" : currentTimeStr,
        @"hostname" : self.serverHostname,
        @"port" : self.serverPort,
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

@end
