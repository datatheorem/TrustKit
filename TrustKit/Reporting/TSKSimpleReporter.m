//
//  TSKSimpleReporter.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleReporter.h"
#import "TSKPinFailureReport.h"
#import "reporting_utils.h"

@interface TSKSimpleReporter()
@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@end


@implementation TSKSimpleReporter


/*
 * Initialize the reporter with the app's bundle id and app version
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion
{
    self = [super init];
    if (self)
    {
        if ((appBundleId == nil) || ([appBundleId length] == 0))
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appBundleId"];
        }
        self.appBundleId = appBundleId;
        
        if ((appVersion == nil) || ([appVersion length] == 0))
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appVersion"];
        }
        self.appVersion = appVersion;
    }
    return self;
}

/*
 * Pin validation failed for a connection to a pinned domain
 * In this implementation for a simple reporter, we're just going to send out the report upon each failure
 */
- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  trust:(SecTrustRef) serverTrust
                          notedHostname:(NSString *) notedHostname
                              reportURIs:(NSArray *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                              knownPins:(NSArray *) knownPins;
{
    // Default port to 443 if not specified
    if (serverPort == nil)
    {
        serverPort = [NSNumber numberWithInt:443];
    }
    
    if (reportURIs == nil)
    {
        [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportURIs: %@ for domain %@",
         reportURIs, notedHostname];
    }
    
    // Create the pin validation failure report
    NSArray *certificateChain = convertTrustToPemArray(serverTrust);
    NSArray *formattedPins = convertPinsToHpkpPins(knownPins);
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppBundleId:self.appBundleId
                                                                       appVersion:self.appVersion
                                                                    notedHostname:notedHostname
                                                                         hostname:serverHostname
                                                                             port:serverPort
                                                                         dateTime:[NSDate date] // Use the current time
                                                                includeSubdomains:includeSubdomains
                                                        validatedCertificateChain:certificateChain
                                                                        knownPins:formattedPins];
    
    // Create the session for sending the report
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration
                                                          delegate:self
                                                     delegateQueue:nil];
    
    // POST the report to all the configured report URIs
    for (NSURL *reportUri in reportURIs)
    {
        NSURLRequest *request = [report requestToUri:reportUri];
        NSURLSessionDataTask *postDataTask = [session dataTaskWithRequest:request
                                                        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                            // We don't do anything here as reports are meant to be sent
                                                            // on a best-effort basis: even if we got an error, there's
                                                            // nothing to do anyway.
                                                        }];
        [postDataTask resume];
    }
}


@end
