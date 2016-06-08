/*
 
 TSKPinFailureReport.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinFailureReport.h"

@implementation TSKPinFailureReport


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
                    validationResult:(TSKPinValidationResult) validationResult
{
    self = [super init];
    if (self)
    {
        _appBundleId = appBundleId;
        _appVersion = appVersion;
        _appPlatform = appPlatform;
        _appVendorId = appVendorId;
        _trustkitVersion = trustkitVersion;
        _hostname = serverHostname;
        _port = serverPort;
        _dateTime = dateTime;
        _notedHostname = notedHostname;
        _includeSubdomains = includeSubdomains;
        _enforcePinning = enforcePinning;
        _validatedCertificateChain = validatedCertificateChain;
        _knownPins = knownPins;
        _validationResult = validationResult;
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
    
    // Create the dictionary
    NSDictionary *requestData = @ {
        @"app-bundle-id" : self.appBundleId,
        @"app-version" : self.appVersion,
        @"app-platform" : self.appPlatform,
        @"app-vendor-id": self.appVendorId,
        @"trustkit-version": self.trustkitVersion,
        @"date-time" : currentTimeStr,
        @"hostname" : self.hostname,
        @"port" : self.port,
        @"noted-hostname" : self.notedHostname,
        @"include-subdomains" : [NSNumber numberWithBool:self.includeSubdomains],
        @"enforce-pinning" : [NSNumber numberWithBool:self.enforcePinning],
        @"validated-certificate-chain" : self.validatedCertificateChain,
        @"known-pins" : self.knownPins,
        @"validation-result": [NSNumber numberWithInt:self.validationResult]
    };
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:(NSJSONWritingOptions)0 error:&error];
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
