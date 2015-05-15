//
//  TSKAppDelegate.m
//  TrustKit
//
//  Created by Angela Chow on 5/15/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "TSKAppDelegate.h"

@implementation TSKAppDelegate

- (void)application:(UIApplication *)application handleEventsForBackgroundURLSession:(NSString *)identifier
  completionHandler:(void (^)())completionHandler
{
    /*
     Store the completion handler. The completion handler is invoked by the view controller if all the upload tasks have been completed).
     */
    self.backgroundSessionCompletionHandler = completionHandler;
}


-(void)applicationWillResignActive:(UIApplication *)application
{
}


-(void)applicationDidBecomeActive:(UIApplication *)application
{
}


@end
