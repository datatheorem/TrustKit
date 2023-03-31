//
//  TSKEndToEndSwizzlingTests.m
//  TrustKit
//
//  Created by Alban Diquet on 7/27/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/configuration_utils.h"



#pragma mark Test NSURLSession delegate

@interface TestNSURLSessionDelegateSwizzling : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
{
    XCTestExpectation *testExpectation;
    
    BOOL _completedConnectionToCloudflare;
    BOOL _completedConnectionToFacebook;
}
@property TSKPinningValidator *validator;


- (instancetype)initWithValidator:(TSKPinningValidator *)validator
                      expectation:(XCTestExpectation *)expectation;

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error;

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler;

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *))completionHandler;


- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

@end


@implementation TestNSURLSessionDelegateSwizzling

- (instancetype)initWithValidator:(TSKPinningValidator *)validator
                      expectation:(XCTestExpectation *)expectation
{
    self = [super init];
    if (self)
    {
        testExpectation = expectation;
        _validator = validator;
        _completedConnectionToCloudflare = NO;
        _completedConnectionToFacebook = NO;
    }
    return self;
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error
{
    NSLog(@"Received error, %@", error);
    if ([task.originalRequest.URL.host isEqualToString:@"www.facebook.com"])
    {
        _completedConnectionToFacebook = YES;
    }
    else if ([task.originalRequest.URL.host isEqualToString:@"www.cloudflare.com"])
    {
        _completedConnectionToCloudflare = YES;
    }
    
    if (_completedConnectionToCloudflare && _completedConnectionToFacebook)
    {
        [testExpectation fulfill];
    }
}

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler
{
    if ([dataTask.originalRequest.URL.host isEqualToString:@"www.facebook.com"])
    {
        _completedConnectionToFacebook = YES;
    }
    else if ([dataTask.originalRequest.URL.host isEqualToString:@"www.cloudflare.com"])
    {
        _completedConnectionToCloudflare = YES;
    }
    
    if (_completedConnectionToCloudflare && _completedConnectionToFacebook)
    {
        [testExpectation fulfill];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    
    NSLog(@"Received redirection");
    if ([task.originalRequest.URL.host isEqualToString:@"www.facebook.com"])
    {
        _completedConnectionToFacebook = YES;
    }
    else if ([task.originalRequest.URL.host isEqualToString:@"www.cloudflare.com"])
    {
        _completedConnectionToCloudflare = YES;
    }
    
    if (_completedConnectionToCloudflare && _completedConnectionToFacebook)
    {
        [testExpectation fulfill];
    }
    
    // Do not follow redirections as they cause two pinning validations
    if (completionHandler)
    {
        completionHandler(nil);
    }
}


- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}


@end



#pragma mark Test suite
@interface TSKEndToEndSwizzlingTests : XCTestCase

@end

@implementation TSKEndToEndSwizzlingTests


- (void)test
{
    // We can only intialize the shared instance once so we run both tests here
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              // Valid pinning configuration
              @"www.cloudflare.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyHashes : @[@"FEzVOUp4dF3gI0ZVPRJhFbSJVXR+uQmMH65xhs1glH4=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]},
              // Invalid pinning configuration
              @"www.facebook.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    
    [TrustKit initSharedInstanceWithConfiguration:trustKitConfig];

    // Configure a validation callback
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    __block BOOL receivedCallForCloudflare = NO;
    __block BOOL receivedCallForFacebook = NO;
    TrustKit.sharedInstance.pinningValidatorCallback = ^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
        // Check the received values
        if ([result.serverHostname isEqualToString:@"www.facebook.com"])
        {
            receivedCallForFacebook = YES;
            XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
            XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedNoMatchingPin);
            
            XCTAssertGreaterThan([result.certificateChain count], (unsigned long)1);
            XCTAssertGreaterThan(result.validationDuration, 0);
            
            XCTAssertEqualObjects(notedHostname, @"www.facebook.com");
            XCTAssertNotNil(notedHostnamePinningPolicy);
        }
        else if ([result.serverHostname isEqualToString:@"www.cloudflare.com"])
        {
            receivedCallForCloudflare = YES;
            XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
            XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
            
            XCTAssertEqualObjects(result.serverHostname,  @"www.cloudflare.com");
            XCTAssertGreaterThan([result.certificateChain count], (unsigned long)1);
            XCTAssertGreaterThan(result.validationDuration, 0);
            
            XCTAssertNotNil(notedHostnamePinningPolicy);
        }
        
        if (receivedCallForCloudflare && receivedCallForFacebook)
        {
            [notifReceivedExpectation fulfill];
        }
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegateSwizzling* delegate = [[TestNSURLSessionDelegateSwizzling alloc] initWithValidator:TrustKit.sharedInstance.pinningValidator
                                                                                                   expectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:ephemeralNSURLSessionConfiguration()
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    // Start two connections
    // One should fail
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.facebook.com/"]];
    [task resume];
    
    // One should succeed
    NSURLSessionDataTask *task2 = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.cloudflare.com/"]];
    [task2 resume];
    
    // Wait for the connection to succeed and ensure a notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
}

@end
