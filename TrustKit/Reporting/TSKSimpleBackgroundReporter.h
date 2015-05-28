//
//  TSKSimpleBackgroundReporter.h
//  TrustKit
//
//  Created by Angela Chow on 5/14/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSKReporterDelegate.h"

/*
 * This is a very simple implementation of a reporter delegate using a background task in sending out the
 * report each time it receives pinValidationFailed.  It does not implement pinValidationSucceeded
 * as it does not care about successful validation.  It also does not try to optimize/throttle the reports sent.
 */
@interface TSKSimpleBackgroundReporter : NSObject <TSKReporterDelegate, NSURLSessionTaskDelegate>

/*
 * Initialize the reporter with the app's bundle id, and app version
 */
- (instancetype)initWithAppBundleId:(NSString *)appBundleId
                         appVersion:(NSString *)appVersion;

@end

