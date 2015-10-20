/*
 
 TSKSimpleReporter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKReporterDelegate.h"


/**
 `TSKSimpleReporter` is a class for uploading pin failure reports.
 
 While TSKSimpleBackgroundReporter is a better implementation in most scenarios as it has a smaller performance impact on the App, the background transfer service cannot be used when running the test suite. Therefore, and only when we run the tests, we fall back to using TSKSimpleReporter.
 
 */
@interface TSKSimpleReporter : NSObject <TSKReporterDelegate, NSURLSessionDelegate>

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes a simple reporter.
 
 @param shouldRateLimitReports Prevent identical pin failure reports from being sent more than once per day.
 
 */
- (instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports;

- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  trust:(SecTrustRef) serverTrust
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                              knownPins:(NSArray *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult;

@end

