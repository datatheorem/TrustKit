/*
 
 AppDelegate.m
 TrustKitDemo
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "AppDelegate.h"
#import <TrustKit/TrustKit.h>

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    // Override point for customization after application launch.
    // Initialize TrustKit
    NSDictionary *trustKitConfig =
    @{
      // Auto-swizzle NSURLSession delegates to add pinning validation
      kTSKSwizzleNetworkDelegates: @YES,
      
      kTSKPinnedDomains: @{
              
              // Pin invalid SPKI hashes to *.yahoo.com to demonstrate pinning failures
              @"yahoo.com" : @{
                      kTSKEnforcePinning:@YES,
                      kTSKIncludeSubdomains:@YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      
                      // Wrong SPKI hashes to demonstrate pinning failure
                      kTSKPublicKeyHashes : @[
                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                              ],
                      
                      // Send reports for pinning failures
                      // Email info@datatheorem.com if you need a free dashboard to see your App's reports
                      kTSKReportUris: @[@"https://overmind.datatheorem.com/trustkit/report"]
                      },
              
              
              // Pin valid SPKI hashes to www.datatheorem.com to demonstrate success
              @"www.datatheorem.com" : @{
                      kTSKEnforcePinning:@YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      
                      // Valid SPKI hashes to demonstrate success
                      kTSKPublicKeyHashes : @[
                              @"lCppFqbkrlJ3EcVFAkeip0+44VaoJUymbnOaEUk7tEU=", // CA key
                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key but 2 pins need to be provided
                              ]
                      }}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    // Demonstrate how to receive pin validation notifications (only useful for performance/metrics)
    NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
    NSOperationQueue *mainQueue = [NSOperationQueue mainQueue];
    [center addObserverForName:kTSKValidationCompletedNotification object:nil
                                         queue:mainQueue usingBlock:^(NSNotification *note) {
                                             NSDictionary* userInfo = [note userInfo];
                                             NSLog(@"Received pinning validation notification:\n  Duration: %@\n  Decision: %@\n  Result: %@\n  Hostname: %@",
                                                   userInfo[kTSKValidationDurationNotificationKey],
                                                   userInfo[kTSKValidationDecisionNotificationKey],
                                                   userInfo[kTSKValidationResultNotificationKey],
                                                   userInfo[kTSKValidationServerHostnameNotificationKey]);
                                                     }];
    
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later.
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application {
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
