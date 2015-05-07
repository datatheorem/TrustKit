//
//  TSKSimpleReporter.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleReporter.h"
@implementation TSKSimpleReporter

BOOL _isTSKSimpleReporterInitialized = NO;

NSString * _appBundleId;
NSString * _appVersion;



/*
 * Initialize the reporter with the app's bundle id and app version
 */
- (void)initWithAppBundleId:(NSString *) appBundleId
                 appVersion:(NSString *) appVersion
{
    if ([appBundleId length] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty appBundleId"];
    }
    _appBundleId = appBundleId;
    
    if ([appVersion length] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty appVersion"];
    }
    _appVersion = appVersion;
    
    _isTSKSimpleReporterInitialized = YES;
    
}

/*
 * Pin validation failed for a connection to a pinned domain
 * In this implementation for a simple reporter, we're just going to send out the report upon each failure
 */
- (void) pinValidationFailed:(NSString *) pinnedDomainStr
              serverHostname:(NSString *) hostnameStr
                  serverPort:(NSNumber *) port
                reportingURL:(NSString *) reportingURLStr
           includeSubdomains:(Boolean) includeSubdomains
            certificateChain:(NSArray *) validatedCertificateChain
                expectedPins:(NSArray *) knownPins
{
    
    if (_isTSKSimpleReporterInitialized == NO)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was not initialized with appid and appversion yet"];
        
    }
    
    if ([pinnedDomainStr length] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty pinnedDomainStr"];
    }

    if ([hostnameStr length] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty serverHostname"];
    }
    
    //default port to 443 if not specified
    if (port == nil)
    {
        port = [NSNumber numberWithInt:443];
    }
    
    NSURL *reportingURL = [NSURL URLWithString:reportingURLStr];
    if (reportingURL == nil)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportingURL: %@ for domain %@",
         reportingURLStr, pinnedDomainStr];
    }
    
    if ([validatedCertificateChain count] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty certificateChain"];
        
    }
    
    if ([knownPins count] == 0)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given empty expectedPins"];

    }
    
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportingURL];
    
    NSDate *currentTime = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *currentTimeStr = [dateFormatter stringFromDate: currentTime];
    
    NSDictionary *requestData = [[NSDictionary alloc] initWithObjectsAndKeys:
                                 _appBundleId, @"app-bundle-id",
                                 _appVersion, @"app-version",
                                 currentTimeStr, @"date-time",
                                 hostnameStr, @"hostname",
                                 port, @"port",
                                 [NSNumber numberWithBool:includeSubdomains], @"include-subdomains",
                                 pinnedDomainStr, @"noted-hostname",
                                 validatedCertificateChain, @"validated-certificate-chain",
                                 knownPins, @"known-pins",
                                 nil];
    
    NSError *error;
    NSData *postData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&error];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody:postData];
    
    
    NSURLSessionDataTask *postDataTask = [session dataTaskWithRequest:request
                                                    completionHandler:^(NSData *data,
                                                                        NSURLResponse *response,
                                                                        NSError *error) {
                                                        
                                                        // You can add something here to handle error conditions.
                                                        // We don't do anything here as reports are meant to be sent
                                                        // on a best-effort basis, so even if we got error, there's
                                                        // nothing we would do anyway.
                                                    }];
    
    [postDataTask resume];
    

}




@end

