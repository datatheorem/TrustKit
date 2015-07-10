/*
 
 TSKRateLimitingBackgroundReporter.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <Foundation/Foundation.h>
#import "TSKSimpleBackgroundReporter.h"

/*
 * Reporter which prevents identical pin failure reports from being sent more than once per day.
 * This is best-effort as the reporter doesn't persist state across App restarts, so if the App
 * get killed, it will start sending reports again.
 * Reports are uploaded using the background transfer service.
 * Also, it only acts on pin failures and does not do anything for successful pin validation.
 */
@interface TSKRateLimitingBackgroundReporter : TSKSimpleBackgroundReporter

- (instancetype)initWithAppBundleId:(NSString *)appBundleId
                         appVersion:(NSString *)appVersion;

@end

