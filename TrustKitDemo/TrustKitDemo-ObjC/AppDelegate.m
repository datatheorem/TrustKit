/*
 
 AppDelegate.m
 TrustKitDemo
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "AppDelegate.h"
#import <TrustKit/TrustKit.h>
#import <TrustKit/TSKPinningValidator.h>
#import <TrustKit/TSKPinningValidatorCallback.h>

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    // Override TrustKit's logger method
    void (^loggerBlock)(NSString *) = ^void(NSString *message)
    {
        NSLog(@"TrustKit log: %@", message);

    };
    [TrustKit setLoggerBlock:loggerBlock];
    
    // Initialize TrustKit
    _trustKitConfig =
    @{
      // Do not auto-swizzle NSURLSession delegates
      kTSKSwizzleNetworkDelegates: @NO,
      
      kTSKPinnedDomains: @{
              
              // Pin invalid SPKI hashes to *.yahoo.com to demonstrate pinning failures
              @"yahoo.com": @{
                      kTSKEnforcePinning: @YES,
                      kTSKIncludeSubdomains: @YES,
                      
                      // Wrong SPKI hashes to demonstrate pinning failure
                      kTSKPublicKeyHashes: @[
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
                      
                      // Valid SPKI hashes to demonstrate success
                      kTSKPublicKeyHashes : @[
                              @"YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=", // Let's Encrypt
                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key but 2 pins need to be provided
                              ]
                      }}};
    
    [TrustKit initSharedInstanceWithConfiguration:_trustKitConfig];
    
    // Demonstrate how to receive pin validation notifications (only useful for performance/metrics)
    [TrustKit sharedInstance].pinningValidatorCallbackQueue = dispatch_get_main_queue();
    [TrustKit sharedInstance].pinningValidatorCallback = ^(TSKPinningValidatorResult *result, NSString *notedHostname, TKSDomainPinningPolicy *policy) {
        NSLog(@"Received pinning validation notification:\n\tDuration: %0.4f\n\tDecision: %ld\n\tResult: %ld\n\tHostname: %@",
              result.validationDuration,
              (long)result.finalTrustDecision,
              (long)result.evaluationResult,
              result.serverHostname);
    };
    
    return YES;
}

@end
