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


#pragma mark Private test methods
@interface TSKNSURLConnectionDelegateProxy(Private)

+(TSKPinValidationResult)getLastTrustDecision;
+(void)resetLastTrustDecision;

@end


#pragma mark Test NSURLConnection delegate with no auth handler
@interface TestNSURLConnectionDelegateNoAuthHandler : NSObject <NSURLConnectionDataDelegate>
{
    XCTestExpectation *testExpectation;
}

@property NSError *lastError;
@property NSURLResponse *lastResponse;

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation;
- (void)connectionDidFinishLoading:(NSURLConnection *)connection;
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response;
- (NSURLRequest *)connection:(NSURLConnection *)connection
             willSendRequest:(NSURLRequest *)request
            redirectResponse:(NSURLResponse *)redirectResponse;

@end


@implementation TestNSURLConnectionDelegateNoAuthHandler {
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
    NSLog(@"Received error, %@", error);
    _lastError = error;
    [testExpectation fulfill];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
}


- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    _lastResponse = response;
    [testExpectation fulfill];
}


- (NSURLRequest *)connection:(NSURLConnection *)connection
             willSendRequest:(NSURLRequest *)request
            redirectResponse:(NSURLResponse *)redirectResponse
{
    NSURLRequest *finalRequest;
    if (redirectResponse == nil)
    {
        // URL canonicalization - not an actual redirection
        finalRequest = request;
    }
    else
    {
        // Do not follow redirections as they cause two pinning validations, thereby changing the lastTrustDecision
        finalRequest = nil;
        NSLog(@"Received redirection %@", redirectResponse);
    }
    return finalRequest;
}

@end


#pragma mark Test NSURLConnection delegate with connection:didReceiveAuthenticationChallenge:
@interface TestNSURLConnectionDelegateDidReceiveAuth : TestNSURLConnectionDelegateNoAuthHandler

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called

- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace;
@end


@implementation TestNSURLConnectionDelegateDidReceiveAuth
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    _wasAuthHandlerCalled = YES;
    [testExpectation fulfill];
}

- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
{
    return YES;
}
@end



#pragma mark Test NSURLConnection delegate with connection:willSendRequestForAuthenticationChallenge:
@interface TestNSURLConnectionDelegateWillSendRequestForAuth : TestNSURLConnectionDelegateNoAuthHandler

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
@end


@implementation TestNSURLConnectionDelegateWillSendRequestForAuth
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
{
    _wasAuthHandlerCalled = YES;
    [testExpectation fulfill];
}

@end


#pragma mark Test suite

// WARNING: For NSURLConnection tests, whenever we connect to a real endpoint as a test, the TLS Session Cache
// will automatically cache the session, causing subsequent connections to the same host to resume the session.
// When that happens, authentication handlers don't get called which would cause our tests to fail.
// As a hacky workaround, every test that connects to an endpoint uses a different domain.
// https://developer.apple.com/library/mac/qa/qa1727/_index.html

// WARNING 2: If the domain sends a redirection, two pinning validation will occur, thereby setting the
// lastTrustDecision to an unexpected value

@interface TSKNSURLConnectionTests : XCTestCase

@end

@implementation TSKNSURLConnectionTests

- (void)setUp {
    [super setUp];
    [TrustKit resetConfiguration];
    [TSKNSURLConnectionDelegateProxy resetLastTrustDecision];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

- (void)tearDown {
    [super tearDown];
}

// NSURLConnection is deprecated - disable Xcode warnings
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"


// Disable auto-swizzling and ensure TrustKit does not get called
// Disabling this test for now as there are no ways to reset the swizzling across different tests
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
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      NSDictionary *userInfo = [note userInfo];
                                                                      // Notification received, check the userInfo
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationDecisionNotificationKey], @(TSKTrustDecisionShouldBlockConnection));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationResultNotificationKey], @(TSKPinValidationResultFailed));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationNotedHostnameNotificationKey], @"www.yahoo.com");
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationServerHostnameNotificationKey], @"www.yahoo.com");
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationCertificateChainNotificationKey] count], (unsigned long)1);
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationDurationNotificationKey] doubleValue], 0);
                                                                      [notifReceivedExpectation fulfill];
                                                                  }];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegateNoAuthHandler *delegate = [[TestNSURLConnectionDelegateNoAuthHandler alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.yahoo.com/"]]
                                   delegate:delegate];
    [connection start];
    
    // Wait for the connection to complete and ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldBlockConnection), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


// Tests a secure connection to https://www.yahoo.com via its IP address in order to simulate a server with an invalid certificate chain and ensure that TrustKit is not disabling certificate validation
- (void)testPinningValidationFailedChainNotTrusted
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      // Ensure a validation notification was NOT posted
                                                                      XCTFail(@"kTSKValidationCompletedNotification should not have been posted");
                                                                  }];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegateNoAuthHandler *delegate = [[TestNSURLConnectionDelegateNoAuthHandler alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://206.190.36.105/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustDecision] == TSKTrustDecisionDomainNotPinned), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although the server's certificate is invalid");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


// Tests a secure connection to https://www.twitter.com by pinning only to the CA public key
- (void)testPinningValidationSucceeded
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.twitter.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"RRM1dGqnDFsCJXBTHky16vi1obOlCgFFn/yOhI/y+ho=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      NSDictionary *userInfo = [note userInfo];
                                                                      // Notification received, check the userInfo
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationDecisionNotificationKey], @(TSKTrustDecisionShouldAllowConnection));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationResultNotificationKey], @(TSKPinValidationResultSuccess));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationNotedHostnameNotificationKey], @"www.twitter.com");
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationServerHostnameNotificationKey], @"www.twitter.com");
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationCertificateChainNotificationKey] count], (unsigned long)1);
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationDurationNotificationKey] doubleValue], 0);
                                                                      [notifReceivedExpectation fulfill];
                                                                  }];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegateNoAuthHandler *delegate = [[TestNSURLConnectionDelegateNoAuthHandler alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:startstartImmediately:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.twitter.com/"]]
                                   delegate:delegate
                                   startImmediately:YES];
    [connection start];
    
    // Wait for the connection to finish and ensure a notification was sent
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldAllowConnection), @"TrustKit rejected a valid certificate");
    XCTAssertNil(delegate.lastError, @"TrustKit triggered an error");
    XCTAssertNotNil(delegate.lastResponse, @"TrustKit prevented a response from being returned");
    XCTAssert([(NSHTTPURLResponse *)delegate.lastResponse statusCode] == 301, @"TrustKit prevented a response from being returned");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


- (void)testNoDelegateWarnings
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.google.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];

    // Run other NSURLConnection methods that we swizzle to display a warning, to ensure they don't crash
    XCTestExpectation *expectation = [self expectationWithDescription:@"Asynchronous request"];
    [NSURLConnection sendAsynchronousRequest:[NSURLRequest requestWithURL:
                                              [NSURL URLWithString:@"https://www.google.com/test"]]
                                       queue:[NSOperationQueue mainQueue]
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               [expectation fulfill];
                           }];
    
    [NSURLConnection sendSynchronousRequest:[NSURLRequest requestWithURL:
                                             [NSURL URLWithString:@"https://www.google.com/test"]]
                          returningResponse:nil error:nil];


    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
}


// Ensure that if the original delegate has an auth handler, it also gets called when pinning validation succeed
// so that we don't disrupt the App's usual flow because of TrustKit's swizzling
- (void)testDidReceiveAuthHandlerGetsCalled
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.apple.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"gMxWOrX4PMQesK9qFNbYBxjBfjUvlkn/vN1n+L9lE5E=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      NSDictionary *userInfo = [note userInfo];
                                                                      // Notification received, check the userInfo
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationDecisionNotificationKey], @(TSKTrustDecisionShouldAllowConnection));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationResultNotificationKey], @(TSKPinValidationResultSuccess));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationNotedHostnameNotificationKey], @"www.apple.com");
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationServerHostnameNotificationKey], @"www.apple.com");
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationCertificateChainNotificationKey] count], (unsigned long)1);
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationDurationNotificationKey] doubleValue], 0);
                                                                      [notifReceivedExpectation fulfill];
                                                                  }];

    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegateDidReceiveAuth"];
    TestNSURLConnectionDelegateDidReceiveAuth *delegate = [[TestNSURLConnectionDelegateDidReceiveAuth alloc] initWithExpectation:expectation];
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.apple.com/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(delegate.wasAuthHandlerCalled, @"TrustKit prevented the original delegate's auth handler from being called.");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


// Ensure that if the original delegate has an auth handler, it also gets called when pinning validation succeed
// so that we don't disrupt the App's usual flow because of TrustKit's swizzling
- (void)testWillSendRequestForAuthHandlerGetsCalled
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.fastmail.fm" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"k2v657xBsOVe1PQRwOsHsw3bsGT2VzIqz5K+59sNQws=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      NSDictionary *userInfo = [note userInfo];
                                                                      // Notification received, check the userInfo
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationDecisionNotificationKey], @(TSKTrustDecisionShouldAllowConnection));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationResultNotificationKey], @(TSKPinValidationResultSuccess));
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationNotedHostnameNotificationKey], @"www.fastmail.fm");
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationServerHostnameNotificationKey], @"www.fastmail.fm");
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationCertificateChainNotificationKey] count], (unsigned long)1);
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationDurationNotificationKey] doubleValue], 0);
                                                                      [notifReceivedExpectation fulfill];
                                                                  }];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegateDidReceiveAuth"];
    TestNSURLConnectionDelegateWillSendRequestForAuth *delegate = [[TestNSURLConnectionDelegateWillSendRequestForAuth alloc] initWithExpectation:expectation];
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.fastmail.fm/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(delegate.wasAuthHandlerCalled, @"TrustKit prevented the original delegate's auth handler from being called.");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


#pragma GCC diagnostic pop
@end
