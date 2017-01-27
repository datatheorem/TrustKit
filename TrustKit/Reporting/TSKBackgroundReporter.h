/*
 
 TSKBackgroundReporter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "../Pinning/ssl_pin_verifier.h"

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
- (nonnull instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports;

///----------------------
/// @name Sending Reports
///----------------------

/**
 Send a pin validation failure report; each argument is described section 3. of RFC 7469.
 */
- (void) pinValidationFailedForHostname:(nonnull NSString *) serverHostname
                                   port:(nullable NSNumber *) serverPort
                                  certificateChain:(nonnull NSArray *) certificateChain
                          notedHostname:(nonnull NSString *) notedHostname
                             reportURIs:(nonnull NSArray<NSURL *> *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                         enforcePinning:(BOOL) enforcePinning
                              knownPins:(nonnull NSSet<NSData *> *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult
                         expirationDate:(nullable NSDate *)knownPinsExpirationDate;

- (void)URLSession:(nonnull NSURLSession *)session task:(nonnull NSURLSessionTask *)task didCompleteWithError:(nullable NSError *)error;

@end

