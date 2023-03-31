//
//  TSKEndToEndNSURLSessionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/public/TSKPinningValidator.h"
#import "../TrustKit/configuration_utils.h"
#import "../TrustKit/public/TSKPinningValidatorResult.h"


#pragma mark Test NSURLSession delegate

@interface TestNSURLSessionDelegate : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
{
    XCTestExpectation *testExpectation;
}
@property TSKPinningValidator *validator;
@property NSError *lastError;
@property NSURLResponse *lastResponse;

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called


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


@implementation TestNSURLSessionDelegate

- (instancetype)initWithValidator:(TSKPinningValidator *)validator
                      expectation:(XCTestExpectation *)expectation
{
    self = [super init];
    if (self)
    {
        testExpectation = expectation;
        _validator = validator;
    }
    return self;
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error
{
    NSLog(@"Received error, %@", error);
    _lastError = error;
    [testExpectation fulfill];
}

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler
{
    _lastResponse = response;
    [testExpectation fulfill];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler
{
    
    NSLog(@"Received redirection");
    [testExpectation fulfill];
    
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
    _wasAuthHandlerCalled = [self.validator handleChallenge:challenge completionHandler:completionHandler];
    if (!_wasAuthHandlerCalled)
    {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}


@end



#pragma mark Test suite
@interface TSKEndToEndNSURLSessionTests : XCTestCase

@end

@implementation TSKEndToEndNSURLSessionTests

- (void)setUp {
    [super setUp];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testPinningValidationFailed
{
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure a validation callback
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.pinningValidatorCallback = ^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
        // Check the received values
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
        XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedNoMatchingPin);
        
        XCTAssertEqualObjects(result.serverHostname,  @"www.yahoo.com");
        XCTAssertGreaterThan([result.certificateChain count], (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        XCTAssertEqualObjects(notedHostname, @"www.yahoo.com");
        XCTAssertNotNil(notedHostnamePinningPolicy);
        
        [notifReceivedExpectation fulfill];
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithValidator:trustKit.pinningValidator expectation:expectation];


    NSURLSession *session = [NSURLSession sessionWithConfiguration:ephemeralNSURLSessionConfiguration()
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.yahoo.com/"]];
    [task resume];
    
    // Wait for the connection to succeed and ensure a notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
}


- (void)testPinningValidationSucceeded
{
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.datatheorem.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyHashes : @[@"cXjPgKdVe6iojP8s0YQJ3rtmDFHTnYZxcYvmYGFiYME=", // CA key for Google Trust Services (cert valid until 27 Jan 2028)
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]}}};
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure a validation callback
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.pinningValidatorCallback = ^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
        // Check the received values
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
        XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
        
        XCTAssertEqualObjects(result.serverHostname,  @"www.datatheorem.com");
        XCTAssertGreaterThan([result.certificateChain count], (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        XCTAssertEqualObjects(notedHostname, @"www.datatheorem.com");
        XCTAssertNotNil(notedHostnamePinningPolicy);
        
        [notifReceivedExpectation fulfill];
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithValidator:trustKit.pinningValidator expectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:ephemeralNSURLSessionConfiguration()
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.datatheorem.com/"]];
    [task resume];
    
    // Wait for the connection to succeed and ensure a notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssertNil(delegate.lastError, @"TrustKit triggered an error");
    XCTAssertNotNil(delegate.lastResponse, @"TrustKit prevented a response from being returned");
    XCTAssert([(NSHTTPURLResponse *)delegate.lastResponse statusCode] == 200, @"TrustKit prevented a response from being returned");
}


// Test a secure connection to https://self-signed.badssl.com with an invalid certificate chain and ensure that TrustKit is not disabling default certificate validation
- (void)testPinningValidationFailedChainNotTrusted
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"self-signed.badssl.com" : @{
                      kTSKEnforcePinning : @NO,  // Do not enforce pinning to only test default SSL validation
                      kTSKPublicKeyHashes : @[@"9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=", // Leaf key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure a validation callback
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.pinningValidatorCallback = ^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
        // Check the received values
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
        XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedInvalidCertificateChain);
        
        XCTAssertEqualObjects(result.serverHostname,  @"self-signed.badssl.com");
        XCTAssertEqual([result.certificateChain count], (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        XCTAssertEqualObjects(notedHostname, @"self-signed.badssl.com");
        XCTAssertNotNil(notedHostnamePinningPolicy);
        
        [notifReceivedExpectation fulfill];
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithValidator:trustKit.pinningValidator expectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:ephemeralNSURLSessionConfiguration()
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://self-signed.badssl.com/"]];
    [task resume];
    
    // Wait for the connection to succeed and ensure a notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error; TrustKit accepted an invalid certificate");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
}


// Test a secure connection to https://self-signed.badssl.com with an invalid certificate chain and ensure that TrustKit is not disabling default certificate validation for domains that are not even pinned
- (void)testPinningValidationFailedChainNotTrustedAndNotPinned
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @NO,  // Do not enforce pinning to only test default SSL validation
                      kTSKPublicKeyHashes : @[@"9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=", // Leaf key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure a validation callback
    trustKit.pinningValidatorCallback = ^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
        // Ensure the validation callback was NOT called
        XCTFail(@"Callback should not have been called");
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithValidator:trustKit.pinningValidator expectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:ephemeralNSURLSessionConfiguration()
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://wrong.host.badssl.com/"]];
    [task resume];
    
    // Wait for the connection to succeed and ensure a notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error; TrustKit accepted an invalid certificate");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
}



@end
