/*
 
 TSKReportsRateLimiter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinFailureReport.h"
@import Foundation;

/*
 * Simple helper class which caches reports for 24 hours to prevent identical reports from being sent twice
 * during this 24 hour period.
 * This is best-effort as the class doesn't persist state across App restarts, so if the App
 * gets killed, it will start sending reports again.
 */
@interface TSKReportsRateLimiter : NSObject

/**
 Determine if the report should be reported or ignored due to the rate limiting policy.

 @param report The report to check whether or not to rate limit
 @return True if the report should be ignored under the rate-limiting policy that
    is in effect.
 */
- (BOOL)shouldRateLimitReport:(TSKPinFailureReport * _Nonnull)report;

@end
