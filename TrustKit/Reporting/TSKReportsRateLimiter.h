/*
 
 TSKReportsRateLimiter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinFailureReport.h"
#import <Foundation/Foundation.h>


/*
 * Simple helper class which caches reports for 24 hours to prevent identical reports from being sent twice
 * during this 24 hour period.
 * This is best-effort as the class doesn't persist state across App restarts, so if the App
 * gets killed, it will start sending reports again.
 */
@interface TSKReportsRateLimiter : NSObject

+ (BOOL) shouldRateLimitReport:(TSKPinFailureReport *)report;

@end



@interface TSKReportsRateLimiter(Private)
// Helper method for running tests
+ (void) setLastReportsCacheResetDate:(NSDate *)date;
@end
