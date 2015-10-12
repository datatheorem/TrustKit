//
//  TSKNSURLSessionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "TSKNSURLSessionDelegateProxy.h"


@interface TSKNSURLSessionDelegateProxy(Private)
+(TSKPinValidationResult)getLastTrustDecision;
@end


@interface TestNSURLSessionTaskDelegate : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
{
    XCTestExpectation *testExpectation;
}
@property NSError *lastError;
@property NSURLResponse *lastResponse;


- (instancetype)initWithExpectation:(XCTestExpectation *)expectation;

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error;

- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
didReceiveResponse:(NSURLResponse * _Nonnull)response
 completionHandler:(void (^ _Nonnull)(NSURLSessionResponseDisposition disposition))completionHandler;

@end


@implementation TestNSURLSessionTaskDelegate

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation
{
    self = [super init];
    if (self)
    {
        testExpectation = expectation;
    }
    return self;
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error
{
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

@end


@interface TSKNSURLSessionTests : XCTestCase

@end

@implementation TSKNSURLSessionTests

- (void)setUp {
    [super setUp];
    [TrustKit resetConfiguration];
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
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionTaskDelegate* delegate = [[TestNSURLSessionTaskDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.yahoo.com/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    
    XCTAssert(([TSKNSURLSessionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldBlockConnection), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
}


// Tests a secure connection to https://www.yahoo.com and forces validation to fail by providing a fake hash, but do not enforce pinning
- (void)testPinningValidationFailedDoNotEnforcePinning
{
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @NO,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionTaskDelegate* delegate = [[TestNSURLSessionTaskDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.yahoo.com/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    
    XCTAssert(([TSKNSURLSessionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldAllowConnection), @"TrustKit blocked a connection although pinning was not enforced");
    XCTAssertNil(delegate.lastError, @"TrustKit triggered an error");
    XCTAssertNotNil(delegate.lastResponse, @"TrustKit did not return a response although pinning was not enforced");
    XCTAssert([(NSHTTPURLResponse *)delegate.lastResponse statusCode] == 200, @"TrustKit did not return a response although pinning was not enforced");
}



- (void)testPinningValidationSucceeded
{
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.datatheorem.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=", // CA key
                                              @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=" // CA key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSession"];
    TestNSURLSessionTaskDelegate *delegate = [[TestNSURLSessionTaskDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.datatheorem.com/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
    
    XCTAssert(([TSKNSURLSessionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldAllowConnection), @"TrustKit rejected a valid certificate");
    XCTAssertNil(delegate.lastError, @"TrustKit triggered an error");
    XCTAssertNotNil(delegate.lastResponse, @"TrustKit prevented a response from being returned");
    XCTAssert([(NSHTTPURLResponse *)delegate.lastResponse statusCode] == 200, @"TrustKit prevented a response from being returned");
}


- (void)testNoDelegateWarnings
{
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Run other NSURLSession methods that we swizzle to display a warning, to ensure they don't crash
    
    // Start a session with a nil delegate
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:nil
                                                     delegateQueue:nil];
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.datatheorem.com/"]];
    [task resume];
    
    // Start a session with +sessionWithConfiguration:
    NSURLSession *session2 = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    NSURLSessionDataTask *task2 = [session2 dataTaskWithURL:[NSURL URLWithString:@"https://www.datatheorem.com/"]];
    [task2 resume];

    // Start a session with +sharedSession
    NSURLSession *session3 = [NSURLSession sharedSession];
    NSURLSessionDataTask *task3 = [session3 dataTaskWithURL:[NSURL URLWithString:@"https://www.datatheorem.com/"]];
    [task3 resume];
}


@end
