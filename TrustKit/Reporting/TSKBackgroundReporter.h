/*
 
 TSKBackgroundReporter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKReporterDelegate.h"


/**
 `TSKSimpleBackgroundReporter` is a class for uploading pin failure reports using the background transfer service.
 
 */
@interface TSKBackgroundReporter : NSObject <TSKReporterDelegate, NSURLSessionTaskDelegate>

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes a background reporter.
 
 @param shouldRateLimitReports Prevent identical pin failure reports from being sent more than once per day.
 @exception NSException Thrown when the App does not have a bundle ID, meaning we're running in unit tests where the background transfer service can't be used.
 
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

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error;

@end

