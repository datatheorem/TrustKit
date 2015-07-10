/*
 
 TSKRateLimitingBackgroundUploader.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKRateLimitingBackgroundUploader.h"
#import "reporting_utils.h"
#include <pthread.h>



// Variables to rate-limit the number of pin failure reports that get sent
static dispatch_once_t _dispatchOnceInit;
static NSMutableSet *_reportsCache = nil;
static pthread_mutex_t _reportsCacheLock;
// We reset the reports cache every 24 hours to ensure identical reports are only sent once per day
#define INTERVAL_BETWEEN_REPORTS_CACHE_RESET 3600*24
static NSDate *_lastReportsCacheResetDate = nil;



@implementation TSKRateLimitingBackgroundUploader


- (instancetype)initWithAppBundleId:(NSString *)appBundleId
                         appVersion:(NSString *)appVersion
{
    // Initialize the background the session in the super class' constructor
    self = [super init];
    
    if (self)
    {
        // Initialize all the internal state for rate-limiting report uploads
        dispatch_once(&_dispatchOnceInit, ^
        {
            // Initialize state for rate-limiting
            pthread_mutex_init(&_reportsCacheLock, NULL);
            _lastReportsCacheResetDate = [NSDate date];
            _reportsCache = [NSMutableSet set];
        });
    }
    return self;
}


- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  trust:(SecTrustRef) serverTrust
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                              knownPins:(NSArray *) knownPins;
{
    // Check if we need to clear the reports cache for rate-limiting
    NSDate *currentDate = [NSDate date];
    NSTimeInterval secondsSinceCacheReset = [currentDate timeIntervalSinceDate:_lastReportsCacheResetDate];
    if (secondsSinceCacheReset > INTERVAL_BETWEEN_REPORTS_CACHE_RESET)
    {
        // Reset the cache
        pthread_mutex_lock(&_reportsCacheLock);
        {
            [_reportsCache removeAllObjects];
            _lastReportsCacheResetDate = currentDate;
        }
        pthread_mutex_unlock(&_reportsCacheLock);
    }

    
    // Create an array containg the gist of the pin failure report
    NSArray *certificateChain = convertTrustToPemArray(serverTrust);
    NSArray *pinFailureInfo = @[notedHostname, serverHostname, serverPort, certificateChain, knownPins];
    
    // Check if the exact same report has already been sent recently
    BOOL shouldRateLimitReport = NO;
    pthread_mutex_lock(&_reportsCacheLock);
    {
        shouldRateLimitReport = [_reportsCache containsObject:pinFailureInfo];
    }
    pthread_mutex_unlock(&_reportsCacheLock);
    
    if (shouldRateLimitReport == NO)
    {
        // An identical report has NOT been sent recently
        // Add this report to the cache for rate-limiting
        pthread_mutex_lock(&_reportsCacheLock);
        {
            [_reportsCache addObject:pinFailureInfo];
        }
        pthread_mutex_unlock(&_reportsCacheLock);
        
        // Send the pin failure report
        [super pinValidationFailedForHostname:serverHostname port:serverPort trust:serverTrust notedHostname:notedHostname reportURIs:reportURIs includeSubdomains:includeSubdomains knownPins:knownPins];
    }
}

@end

