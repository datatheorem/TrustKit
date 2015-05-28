//
//  TSKSimpleReporter.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleReporter.h"
#import "TSKPinFailureReport.h"


@interface TSKSimpleReporter()
@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic) BOOL isTSKSimpleReporterInitialized;
@end


@implementation TSKSimpleReporter

/*
 * Initialize the reporter with the app's bundle id and app version
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion
{
    
    self = [super init];
    if (self) {
        // Custom initialization
        if ([appBundleId length] == 0)
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appBundleId"];
        }
        self.appBundleId = appBundleId;
        
        if ([appVersion length] == 0)
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appVersion"];
        }
        self.appVersion = appVersion;
        self.isTSKSimpleReporterInitialized = YES;
        
    }
    return self;
    
}

/*
 * Pin validation failed for a connection to a pinned domain
 * In this implementation for a simple reporter, we're just going to send out the report upon each failure
 */
- (void) pinValidationFailed:(NSString *) pinnedDomainStr
              serverHostname:(NSString *) hostnameStr
                  serverPort:(NSNumber *) port
                reportingURL:(NSString *) reportingURLStr
           includeSubdomains:(BOOL) includeSubdomains
            certificateChain:(NSArray *) validatedCertificateChain
                expectedPins:(NSArray *) knownPins
{
    
    if (self.isTSKSimpleReporterInitialized == NO)
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
    
    // Create the pin validation failure report
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppBundleId:self.appBundleId
                                                                          appVersion:self.appVersion
                                                                   notedHostname:pinnedDomainStr
                                                                  serverHostname:hostnameStr
                                                                            port:port
                                                                         dateTime:[NSDate date] // Use the current time
                                                               includeSubdomains:includeSubdomains
                                                       validatedCertificateChain:validatedCertificateChain
                                                                       knownPins:knownPins];
    
    // POST it to the report uri
    NSURLRequest *request = [report requestToUri:reportingURL];
    
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration delegate:self delegateQueue:nil];
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

