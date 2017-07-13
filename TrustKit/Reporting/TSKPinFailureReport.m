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
                            validationResult:(TSKTrustEvaluationResult)validationResult
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
    // NSDateFormatter (and NSNumberFormatter) is extremely expensive to initialize, doesn't
    // change, and is listed as explicitely thread safe, so lets reuse the instance.
    static NSDateFormatter *DateTimeFormatter = nil;
    static NSDateFormatter *DateFormatter = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        /// Date AND time formatter for JSON
        DateTimeFormatter = ({
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            
            // Explicitely set the locale to avoid an iOS 8 bug
            // http://stackoverflow.com/questions/29374181/nsdateformatter-hh-returning-am-pm-on-ios-8-device
            df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
            
            df.dateFormat = @"yyyy-MM-dd'T'HH:mm:ss'Z'";
            df.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
            df;
        });
        
        /// Date ONLY formatter
        DateFormatter = ({
            NSDateFormatter *df = [[NSDateFormatter alloc] init];
            
            // Explicitely set the locale to avoid an iOS 8 bug
            // http://stackoverflow.com/questions/29374181/nsdateformatter-hh-returning-am-pm-on-ios-8-device
            df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
            
            df.dateFormat = @"yyyy-MM-dd";
            df.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
            df;
        });
    });
    
    id dateStr = [NSNull null];
    if (self.dateTime)
    {
        dateStr = [DateTimeFormatter stringFromDate:self.dateTime] ?: [NSNull null];
    }
    
    id expirationDateStr = [NSNull null];
    if (self.knownPinsExpirationDate)
    {
        // For the expiration date, only return the expiration day, as specified in the pinning policy
        expirationDateStr = [DateFormatter stringFromDate:self.knownPinsExpirationDate] ?: [NSNull null];
    }
    
    // Create the dictionary
    NSDictionary *requestData = @{
        @"app-bundle-id":               self.appBundleId,
        @"app-version":                 self.appVersion,
        @"app-platform":                self.appPlatform,
        @"app-platform-version":        self.appPlatformVersion,
        @"app-vendor-id":               self.appVendorId,
        @"trustkit-version":            self.trustkitVersion,
        @"date-time":                   dateStr,
        @"hostname":                    self.hostname,
        @"port":                        self.port,
        @"noted-hostname":              self.notedHostname,
        @"include-subdomains":          @(self.includeSubdomains),
        @"enforce-pinning":             @(self.enforcePinning),
        @"validated-certificate-chain": self.validatedCertificateChain,
        @"known-pins":                  self.knownPins,
        @"validation-result":           @(self.validationResult),
        @"known-pins-expiration-date":  expirationDateStr
    };
    
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:requestData options:(NSJSONWritingOptions)0 error:&error];
    // FIXME: error is unhandled.
    return jsonData;
}


- (nonnull NSMutableURLRequest *)requestToUri:(NSURL *)reportUri
{
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportUri];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [self json];
    return request;
}


@end
