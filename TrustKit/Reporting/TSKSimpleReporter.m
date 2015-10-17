/*
 
 TSKSimpleReporter.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKSimpleReporter.h"
#import "TrustKit+Private.h"
#import "TSKPinFailureReport.h"
#import "reporting_utils.h"
#import "TSKReportsRateLimiter.h"

#if TARGET_OS_IPHONE
@import UIKit; // For accessing the IDFV
#endif




@interface TSKSimpleReporter()
@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic, strong) NSString * appVendorId;
@property BOOL shouldRateLimitReports;
@property(nonatomic, strong) NSURLSession *session;
@end


@implementation TSKSimpleReporter


- (instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports
{
    self = [super init];
    if (self)
    {
        self.shouldRateLimitReports = shouldRateLimitReports;
        
        // Retrieve the App's information
#if TARGET_OS_IPHONE
        // On iOS use the IDFV
        self.appVendorId = [[[UIDevice currentDevice] identifierForVendor]UUIDString];
#else
        // On OS X, don't use anything for now
        self.appVendorId = @"OS-X";
#endif
        
        CFBundleRef appBundle = CFBundleGetMainBundle();
        self.appBundleId = (__bridge NSString *)CFBundleGetIdentifier(appBundle);
        self.appVersion =  (__bridge NSString *)CFBundleGetValueForInfoDictionaryKey(appBundle, kCFBundleVersionKey);
        
        if (self.appBundleId == nil)
        {
            // Should only happen when running tests
            self.appBundleId = @"N/A";
        }
        
        if (self.appVersion == nil)
        {
            self.appVersion = @"N/A";
        }
    
        
        // Create the session for sending the reports
        self.session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    }
    return self;
}


- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  trust:(SecTrustRef) serverTrust
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                              knownPins:(NSArray *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult;
{
    // Pin validation failed for a connection to a pinned domain
    
    // Default port to 0 if not specified
    if (serverPort == nil)
    {
        serverPort = [NSNumber numberWithInt:0];
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
                                                                        knownPins:formattedPins
                                                                 validationResult:validationResult
                                                                    appVendorId:self.appVendorId];
    
    
    // Should we rate-limit this report?
    if (self.shouldRateLimitReports && [TSKReportsRateLimiter shouldRateLimitReport:report])
    {
        // We recently sent the exact same report; do not send this report
        TSKLog(@"Pin failure report for %@ was not sent due to rate-limiting", serverHostname);
        return;
    }

    
    // POST the report to all the configured report URIs
    for (NSURL *reportUri in reportURIs)
    {
        NSURLRequest *request = [report requestToUri:reportUri];
        NSURLSessionDataTask *postDataTask = [self.session dataTaskWithRequest:request
                                                             completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                                                            // We don't do anything here as reports are meant to be sent
                                                            // on a best-effort basis: even if we got an error, there's
                                                            // nothing to do anyway.
                                                        }];
        [postDataTask resume];
    }
}


@end
