/*
 
 TSKPinFailureReport.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinFailureReport.h"

@implementation TSKPinFailureReport


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
                            validationResult:(TSKPinValidationResult)validationResult
                              expirationDate:(nullable NSDate *)knownPinsExpirationDate
{
    self = [super init];
    if (self)
    {
        _appBundleId = appBundleId;
        _appVersion = appVersion;
        _appPlatform = appPlatform;
        _appVendorId = appVendorId;
        _trustkitVersion = trustkitVersion;
        _appPlatformVersion = appPlatformVersion;
        _hostname = serverHostname;
        _port = serverPort;
        _dateTime = dateTime;
        _notedHostname = notedHostname;
        _includeSubdomains = includeSubdomains;
        _enforcePinning = enforcePinning;
        _validatedCertificateChain = validatedCertificateChain;
        _knownPins = knownPins;
        _validationResult = validationResult;
        _knownPinsExpirationDate = knownPinsExpirationDate;
    }
    return self;
}


- (nonnull NSData *)json;
{
    // Convert the date to a string
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    
    // Explicitely set the locale to avoid an iOS 8 bug
    // http://stackoverflow.com/questions/29374181/nsdateformatter-hh-returning-am-pm-on-ios-8-device
    [dateFormatter setLocale:[[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"]];
    
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *currentTimeStr = [dateFormatter stringFromDate: self.dateTime];
    
    id expirationDateStr = [NSNull null];
    if (self.knownPinsExpirationDate)
    {
        // For the expiration date, only return the expiration day, as specified in the pinning policy
        [dateFormatter setDateFormat:@"yyyy-MM-dd"];
        expirationDateStr = [dateFormatter stringFromDate:self.knownPinsExpirationDate];
    }
    
    // Create the dictionary
    NSDictionary *requestData = @{
        @"app-bundle-id" : self.appBundleId,
        @"app-version" : self.appVersion,
        @"app-platform" : self.appPlatform,
        @"app-platform-version" : self.appPlatformVersion,
        @"app-vendor-id" : self.appVendorId,
        @"trustkit-version" : self.trustkitVersion,
        @"date-time" : currentTimeStr,
        @"hostname" : self.hostname,
        @"port" : self.port,
        @"noted-hostname" : self.notedHostname,
        @"include-subdomains" : [NSNumber numberWithBool:self.includeSubdomains],
        @"enforce-pinning" : [NSNumber numberWithBool:self.enforcePinning],
        @"validated-certificate-chain" : self.validatedCertificateChain,
        @"known-pins" : self.knownPins,
        @"validation-result": [NSNumber numberWithInt:self.validationResult],
        @"known-pins-expiration-date": expirationDateStr
    };
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:(NSJSONWritingOptions)0 error:&error];
    return jsonData;
}


- (nonnull NSMutableURLRequest *)requestToUri:(NSURL *)reportUri
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportUri];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:[self json]];
    return request;
}


@end
