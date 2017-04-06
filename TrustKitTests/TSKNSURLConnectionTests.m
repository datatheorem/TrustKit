//
//  TSKNSURLConnectionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/TrustKit.h"
#import "../TrustKit/Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import <OCMock/OCMock.h>

@interface TSKNSURLConnectionDelegateProxy (TestSupport)
@property (nonatomic) TSKPinValidationResult lastTrustDecision;
-(BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection;
@end

@interface TrustKit (TestSupport)
+ (void)resetConfiguration;
@end

/*
#pragma mark Test NSURLConnection delegate with no auth handler
@interface TestNSURLConnectionDelegateNoAuthHandler : NSObject <NSURLConnectionDataDelegate>
{
    XCTestExpectation *_testExpectation;
}

@property TrustKit *trustKit;
@property NSError *lastError;
@property NSURLResponse *lastResponse;

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation;
@end

@implementation TestNSURLConnectionDelegateNoAuthHandler

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation trustKit:(TrustKit *)trustKit
{
    self = [super init];
    if (self) {
        _testExpectation = expectation;
        _trustKit = trustKit;
    }
    return self;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"Received error, %@", error);
    _lastError = error;
    [_testExpectation fulfill];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data { }

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    _lastResponse = response;
    [_testExpectation fulfill];
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
 
 
 @implementation TestNSURLConnectionDelegateDidReceiveAuth
 - (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
 {
 _wasAuthHandlerCalled = YES;
 [_testExpectation fulfill];
 }
 
 - (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace
 {
 return YES;
 }
 @end
 
 
 
 #pragma mark Test NSURLConnection delegate with connection:didReceiveAuthenticationChallenge:
 @interface TestNSURLConnectionDelegateDidReceiveAuth : TestNSURLConnectionDelegateNoAuthHandler
 
 @property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called
 
 - (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;
 - (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace;
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
 [_testExpectation fulfill];
 }
 
 @end
*/

///// These are classes that respond to specific combinations of methods. Mock the methods
///// as needed for the tests.

@interface TestModeADelegate : NSObject<NSURLConnectionDelegate, NSURLAuthenticationChallengeSender>
@end

@implementation TestModeADelegate
- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge { }
- (void)fakeMethod { } // used in some tests

// Protocol requirements
- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)performDefaultHandlingForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
@end

@interface TestModeBDelegate : NSObject<NSURLConnectionDelegate, NSURLAuthenticationChallengeSender>
@property (nonatomic) BOOL shouldAuthenticate; // the value returned by `canAuthenticate...:`
@end

@implementation TestModeBDelegate
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return self.shouldAuthenticate;
}
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge { }

// Protocol requirements
- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)performDefaultHandlingForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
@end

/////


#pragma mark Test suite

// WARNING: For NSURLConnection tests, whenever we connect to a real endpoint as a test, the TLS Session Cache
// will automatically cache the session, causing subsequent connections to the same host to resume the session.
// When that happens, authentication handlers don't get called which would cause our tests to fail.
// As a hacky workaround, every test that connects to an endpoint uses a different domain.
// https://developer.apple.com/library/mac/qa/qa1727/_index.html

// WARNING 2: If the domain sends a redirection, two pinning validation will occur, thereby setting the
// lastTrustDecision to an unexpected value

@interface TSKNSURLConnectionTests : XCTestCase {
    
}
@end

@implementation TSKNSURLConnectionTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // NSURLConnection is deprecated - disable Xcode warnings

#pragma mark - respondsToSelector override

- (void)test_respondsToSelector_alwaysTrueForWillSendRequest
{
    TSKNSURLConnectionDelegateProxy *proxy;
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:[TestModeADelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:[TestModeBDelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
}

- (void)respondsToSelector_trueForOriginalMethods
{
    TSKNSURLConnectionDelegateProxy *proxy;
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:[TestModeADelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:[TestModeBDelegate new]];
    XCTAssertFalse([proxy respondsToSelector:@selector(fakeMethod)]);
}

- (void)test_respondsToSelector_falseForUnimplementedMethods
{
    TSKNSURLConnectionDelegateProxy *proxy;
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:[TestModeADelegate new]];
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"argle:bargle:")]);
}

//#pragma mark - forwardingTargetForSelector override
//
//- (void)test_respondsToSelector_forwardsTargetForSelector
//{
//    TestModeADelegate *delegate = OCMStrictClassMock([TestModeADelegate class]);
//    OCMExpect([delegate fakeMethod]);
//
//    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate];
//    [(id)proxy fakeMethod];
//
//    OCMVerifyAll((id)delegate);
//    [(id)delegate stopMocking];
//}

#pragma mark - forwardToOriginalDelegateAuthenticationChallenge

- (void)test_forwardToOriginalDelegateAuthenticationChallenge_respondsToWillSend
{
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] init];
    
    TestModeADelegate *delegate = OCMStrictClassMock([TestModeADelegate class]);
    OCMExpect([delegate connection:cnxn willSendRequestForAuthenticationChallenge:challenge]);
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate];
    [(id)proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn];

    OCMVerifyAll((id)delegate);
    [(id)delegate stopMocking];
}

- (void)test_forwardToOriginalDelegateAuthenticationChallenge_respondsToCanAuthenticate
{
    TestModeBDelegate *delegate = OCMStrictClassMock([TestModeBDelegate class]);
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] init];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    OCMExpect([delegate connection:cnxn canAuthenticateAgainstProtectionSpace:space]).andReturn(YES);
    OCMExpect([delegate connection:cnxn didReceiveAuthenticationChallenge:challenge]);
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate];
    [(id)proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn];
    
    OCMVerifyAll((id)delegate);
    [(id)delegate stopMocking];
}

#pragma mark - connection:willSendRequestForAuthenticationChallenge:

- (void)test_connectionWillSendRequestForAuthenticationChallenge_notServerTrust
{
    TestModeADelegate *delegate = OCMStrictClassMock([TestModeADelegate class]);
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate];
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"host" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    // Expect fallthrough because this connection was not blocked.
    OCMExpect([delegate connection:cnxn willSendRequestForAuthenticationChallenge:challenge]);
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    OCMVerifyAll((id)delegate);
}

- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustA_allow
{
    TestModeADelegate *delegate = OCMStrictClassMock([TestModeADelegate class]);
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    [TrustKit initializeWithConfiguration:@{}];
    [TrustKit sharedInstance].pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMExpect([proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn]);
    OCMStub([proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge]).andForwardToRealObject();
    OCMExpect([delegate performDefaultHandlingForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [TrustKit sharedInstance].pinningValidator = [TSKPinningValidator new];
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}

- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustB_allow
{
    TestModeBDelegate *delegate = OCMPartialMock([TestModeBDelegate new]);
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    [TrustKit initializeWithConfiguration:@{}];
    [TrustKit sharedInstance].pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMStub([proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge]).andForwardToRealObject();
    // Test that the forward method was called – that method was tested in it's own unit tests.
    OCMExpect([proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn]).andReturn(NO);
    OCMExpect([delegate performDefaultHandlingForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [TrustKit sharedInstance].pinningValidator = [TSKPinningValidator new];
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}

// Test the block case: only need to test for one because the failure handling is identical
- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustB_block
{
    TestModeBDelegate *delegate = OCMPartialMock([TestModeBDelegate new]);
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    [TrustKit initializeWithConfiguration:@{}];
    [TrustKit sharedInstance].pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldBlockConnection);
    OCMExpect([delegate cancelAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [TrustKit sharedInstance].pinningValidator = [TSKPinningValidator new];
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}



// TODO: add swizzling tests to ensure the above tested methods are properly invoked.


// LEGACY BELOW



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

/*
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
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.validationDelegateCallback = ^(TSKPinningValidatorResult *result) {
        // Notification received, check the userInfo
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
        XCTAssertEqual(result.validationResult, TSKPinValidationResultFailed);
        XCTAssertEqualObjects(result.notedHostname, @"www.yahoo.com");
        XCTAssertEqualObjects(result.serverHostname, @"www.yahoo.com");
        XCTAssertGreaterThan(result.certificateChain.count, (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        [notifReceivedExpectation fulfill];
    };
    
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
}


// Tests a secure connection to https://self-signed.badssl.com with an invalid certificate chain and ensure that TrustKit is not disabling default certificate validation
- (void)testPinningValidationFailedChainNotTrusted
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"self-signed.badssl.com" : @{
                      kTSKEnforcePinning : @NO,  // Do not enforce pinning to ensure default SSL validation is still enabled
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=", // Leaf key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegateNoAuthHandler *delegate = [[TestNSURLConnectionDelegateNoAuthHandler alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://self-signed.badssl.com/"]]
                                   delegate:delegate];
    [connection start];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(([TSKNSURLConnectionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldBlockConnection), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although the server's certificate is invalid");
}


// Tests a secure connection to https://self-signed.badssl.com with an invalid certificate chain and ensure that TrustKit is not disabling default certificate validation for domains that are not even pinned
- (void)testPinningValidationFailedChainNotTrustedAndNotPinned
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              // Different domain than the one we are connecting to
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @NO,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=", // Leaf key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    trustKit.validationDelegateCallback = ^(TSKPinningValidatorResult *result) {
        // Ensure a validation notification was NOT posted
        XCTFail(@"kTSKValidationCompletedNotification should not have been posted");
    };
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegateNoAuthHandler *delegate = [[TestNSURLConnectionDelegateNoAuthHandler alloc] initWithExpectation:expectation];
    // Use -initWithRequest:delegate:
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://self-signed.badssl.com/"]]
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
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.validationDelegateCallback = ^(TSKPinningValidatorResult *result) {
        // Notification received, check the userInfo
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
        XCTAssertEqual(result.validationResult, TSKPinValidationResultSuccess);
        XCTAssertEqualObjects(result.notedHostname, @"www.twitter.com");
        XCTAssertEqualObjects(result.serverHostname, @"www.twitter.com");
        XCTAssertGreaterThan(result.certificateChain.count, (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        [notifReceivedExpectation fulfill];
    };
    
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
    
    [TrustKit resetConfiguration];
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
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.validationDelegateCallback = ^(TSKPinningValidatorResult *result) {
        // Notification received, check the userInfo
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
        XCTAssertEqual(result.validationResult, TSKPinValidationResultSuccess);
        XCTAssertEqualObjects(result.notedHostname, @"www.apple.com");
        XCTAssertEqualObjects(result.serverHostname, @"www.apple.com");
        XCTAssertGreaterThan(result.certificateChain.count, (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        [notifReceivedExpectation fulfill];
    };
    
    // Configure notification listener
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
                      kTSKPublicKeyHashes : @[@"5kJvNEMw0KjrCAu7eXY5HZdvyCS13BbA0VJG1RSP91w=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Configure notification listener
    XCTestExpectation *notifReceivedExpectation = [self expectationWithDescription:@"TestNotificationReceivedExpectation"];
    trustKit.validationDelegateCallback = ^(TSKPinningValidatorResult *result) {
        // Notification received, check the userInfo
        XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
        XCTAssertEqual(result.validationResult, TSKPinValidationResultSuccess);
        XCTAssertEqualObjects(result.notedHostname, @"www.fastmail.fm");
        XCTAssertEqualObjects(result.serverHostname, @"www.fastmail.fm");
        XCTAssertGreaterThan(result.certificateChain.count, (unsigned long)1);
        XCTAssertGreaterThan(result.validationDuration, 0);
        
        [notifReceivedExpectation fulfill];
    };
    
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
}

*/
#pragma GCC diagnostic pop
@end
