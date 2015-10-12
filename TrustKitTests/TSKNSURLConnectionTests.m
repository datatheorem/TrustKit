//
//  TSKNSURLConnectionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "TSKNSURLConnectionDelegateProxy.h"

@interface TSKNSURLConnectionDelegateProxy(Private)
+(TSKPinValidationResult)getLastTrustKitValidationResult;
@end


@interface TestNSURLConnectionDelegate : NSObject <NSURLConnectionDataDelegate>
{
    XCTestExpectation *testExpectation;
}

@property NSError *lastError;
@property NSURLResponse *lastResponse;

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation;
- (void)connectionDidFinishLoading:(NSURLConnection *)connection;
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error;
- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response;
@end


@implementation TestNSURLConnectionDelegate {
}

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation
{
    self = [super init];
    if (self)
    {
        testExpectation = expectation;
    }
    return self;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    _lastError = error;
    [testExpectation fulfill];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse
{
    return cachedResponse;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    _lastResponse = response;
    [testExpectation fulfill];
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse
{
    return request;
}

@end


@interface TSKNSURLConnectionTests : XCTestCase

@end

@implementation TSKNSURLConnectionTests

- (void)setUp {
    [super setUp];
    [TrustKit resetConfiguration];
}

- (void)tearDown {
    [super tearDown];
}

// NSURLConnection is deprecated - disable Xcode warnings
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


// Disable auto-swizzling and ensure TrustKit does not get called
/*
- (void)testSwizzleNetworkDelegatesDiabled
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @NO,
      kTSKPinnedDomains :
          @{
              @"www.reddit.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegate* delegate = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.yahoo.com/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
    
    // The initial value for getLastTrustKitValidationResult is -1 when no pinning validation has been done yet
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustKitValidationResult] < 0), @"TrustKit was called although swizzling was disabled");
}
*/


// Tests a secure connection to https://www.yahoo.com and forces validation to fail by providing a fake hash
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

    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegate* delegate = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.yahoo.com/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
    {
        if (error)
        {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
    
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustKitValidationResult] == TSKPinValidationResultFailed), @"TrustKit accepted an invalid certificate");
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
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegate* delegate = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    // Use +connectionWithRequest:delegate:
    NSURLConnection *connection = [NSURLConnection
                                   connectionWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.yahoo.com/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustKitValidationResult] == TSKPinValidationResultFailed), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNotNil(delegate.lastResponse, @"TrustKit did not return a response although pinning was not enforced");
    XCTAssert([(NSHTTPURLResponse *)delegate.lastResponse statusCode] == 200, @"TrustKit did not return a response although pinning was not enforced");
}


// Tests a secure connection to https://www.datatheorem.com by pinning only to the CA public key
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
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegate* delegate = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:startstartImmediately:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.datatheorem.com/"]]
                                   delegate:delegate
                                   startImmediately:YES];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    
    NSLog(@"lol %ld",(long)[TSKNSURLConnectionDelegateProxy getLastTrustKitValidationResult]);
    
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustKitValidationResult] == TSKPinValidationResultSuccess), @"TrustKit rejected a valid certificate");
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

    // Run other NSURLConnection methods that we swizzle to display a warning, to ensure they don't crash
    XCTestExpectation *expectation = [self expectationWithDescription:@"Asynchronous request"];
    [NSURLConnection sendAsynchronousRequest:[NSURLRequest requestWithURL:
                                              [NSURL URLWithString:@"https://www.datatheorem.com/test"]]
                                       queue:[NSOperationQueue mainQueue]
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               [expectation fulfill];
                           }];
    
    [NSURLConnection sendSynchronousRequest:[NSURLRequest requestWithURL:
                                             [NSURL URLWithString:@"https://www.datatheorem.com/test"]]
                          returningResponse:nil error:nil];


    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
}

#pragma GCC diagnostic pop
@end
