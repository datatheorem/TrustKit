//
//  TSKAppDelegate.h
//  TrustKit
//
//  Created by Angela Chow on 5/15/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

@import UIKit;

@interface TSKAppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;
@property (copy) void (^backgroundSessionCompletionHandler)();

@end
