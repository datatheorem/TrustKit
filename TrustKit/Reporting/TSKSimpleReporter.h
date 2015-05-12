//
//  TSKSimpleReporter.h
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSKReporterDelegate.h"

/* 
 * This is a very simple implementation of a reporter delegate showing how it just sends out a POST request
 * with the report each time it receives pinValidationFailed.  It does not implement pinValidationSucceeded
 * as it does not care about successful validation.  It also does not try to optimize/throttle the reports sent.
 */
@interface TSKSimpleReporter : NSObject <TSKReporterDelegate, NSURLSessionDelegate>

@end

