/*
 
 TSKBackgroundReporter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "ssl_pin_verifier.h"

/**
 `TSKSimpleBackgroundReporter` is a class for uploading pin failure reports using the background transfer service.
 
 */
@interface TSKBackgroundReporter : NSObject <NSURLSessionTaskDelegate>

///---------------------
/// @name Initialization
///---------------------

/**
 Initializes a background reporter.
 
 @param shouldRateLimitReports Prevent identical pin failure reports from being sent more than once per day.
 @exception NSException Thrown when the App does not have a bundle ID, meaning we're running in unit tests where the background transfer service can't be used.
 
 */
- (instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports;

///----------------------
/// @name Sending Reports
///----------------------

/**
 Send a pin validation failure report; each argument is described section 3. of RFC 7469.
 */
- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  certificateChain:(NSArray *) certificateChain
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray<NSURL *> *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                         enforcePinning:(BOOL) enforcePinning
                              knownPins:(NSSet<NSData *> *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult;

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error;

@end

