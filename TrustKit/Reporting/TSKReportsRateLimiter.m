/*
 
 TSKReportsRateLimiter.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKReportsRateLimiter.h"
#import "reporting_utils.h"

static const NSTimeInterval kIntervalBetweenReportsCacheReset = 3600 * 24;

@interface TSKReportsRateLimiter ()

/** Cache to rate-limit the number of pin failure reports that get sent */
@property (nonatomic) NSMutableSet *reportsCache;

/** We reset the reports cache every 24 hours to ensure identical reports are only sent once per day */
@property (nonatomic) NSDate *lastReportsCacheResetDate;

/** Concurrent queue for multi-reader, single-writer to the reports cache using dispatch barriers */
@property (nonatomic) dispatch_queue_t reportsCacheQueue;

@end

@implementation TSKReportsRateLimiter

- (instancetype)init
{
    self = [super init];
    if (self) {
        // Initialize all the internal state for rate-limiting report uploads
        _reportsCache = [NSMutableSet set];
        _lastReportsCacheResetDate = [NSDate date];
        _reportsCacheQueue = dispatch_queue_create("TSKReportsRateLimiter", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (BOOL)shouldRateLimitReport:(TSKPinFailureReport *)report
{
    NSParameterAssert(report);
    
    // Check if we need to clear the reports cache for rate-limiting
    NSTimeInterval secondsSinceCacheReset = -[self.lastReportsCacheResetDate timeIntervalSinceNow];
    
    // Create an array containg the gist of the pin failure report; do not include the dates
    NSArray *pinFailureInfo = @[ report.notedHostname,
                                 report.hostname,
                                 report.port,
                                 report.validatedCertificateChain,
                                 report.knownPins,
                                 @(report.validationResult) ];
    
    __block BOOL shouldRateLimitReport = NO;
    __weak typeof(self) weakSelf = self;
    dispatch_sync(self.reportsCacheQueue, ^{
        typeof(self) strongSelf = weakSelf;
        
        if (secondsSinceCacheReset > kIntervalBetweenReportsCacheReset)
        {
            // Reset the cache
            [strongSelf.reportsCache removeAllObjects];
            strongSelf.lastReportsCacheResetDate = [NSDate date];
        }
        
        // Check if the exact same report has already been sent recently
        shouldRateLimitReport = [strongSelf.reportsCache containsObject:pinFailureInfo];
        if (shouldRateLimitReport == NO)
        {
            // An identical report has NOT been sent recently
            // Add this report to the cache for rate-limiting
            [strongSelf.reportsCache addObject:pinFailureInfo];
        }
    });
    
    return shouldRateLimitReport;
}

- (void)setLastReportsCacheResetDate:(NSDate *)lastReportsCacheResetDate
{
    NSParameterAssert(lastReportsCacheResetDate);
    _lastReportsCacheResetDate = lastReportsCacheResetDate;
}

@end

