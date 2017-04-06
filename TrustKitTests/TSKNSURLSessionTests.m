//
//  TSKNSURLSessionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/TrustKit.h"
#import "../TrustKit/TSKPinningValidator.h"
#import "../TrustKit/TSKPinningValidatorResult.h"
#import "../TrustKit/Swizzling/TSKNSURLSessionDelegateProxy.h"

#import <OCMock/OCMock.h>

@interface TrustKit (TestSupport)
+ (void)resetConfiguration;
@end

@interface TSKNSURLSessionDelegateProxy (TestSupport)
@property (nonatomic) id<NSURLSessionDelegate, NSURLSessionTaskDelegate> originalDelegate;
@property (nonatomic) TSKPinValidationResult lastTrustDecision;

- (BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                                       completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler
                                              forSession:(NSURLSession * _Nonnull)session;

- (void)common_URLSession:(NSURLSession * _Nonnull)session
                challenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
        completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                             NSURLCredential * _Nullable credential))completionHandler;

@end

/*
#pragma mark Private test methods
@interface TSKNSURLSessionDelegateProxy(Private)

+(TSKPinValidationResult)getLastTrustDecision;
+(void)resetLastTrustDecision;

@end


#pragma mark Test NSURLSession delegate with no auth handler
@interface TestNSURLSessionDelegate : NSObject <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
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

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task willPerformHTTPRedirection:(NSHTTPURLResponse *)response newRequest:(NSURLRequest *)request completionHandler:(void (^)(NSURLRequest *))completionHandler;

@end


@implementation TestNSURLSessionDelegate

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
    
    // Do not follow redirections as they cause two pinning validations, thereby changing the lastTrustDecision
    if (completionHandler)
    {
        completionHandler(nil);
    }
}

@end


#pragma mark Test NSURLSession delegate with URLSession:task:didReceiveChallenge:completionHandler:
@interface TestNSURLSessionDelegateTaskDidReceiveChallenge : TestNSURLSessionDelegate

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

@end


@implementation TestNSURLSessionDelegateTaskDidReceiveChallenge

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    _wasAuthHandlerCalled = YES;
    [testExpectation fulfill];
}

@end


#pragma mark Test NSURLSession delegate with -URLSession:didReceiveChallenge:completionHandler:
@interface TestNSURLSessionDelegateSessionDidReceiveChallenge : TestNSURLSessionDelegate

@property BOOL wasAuthHandlerCalled; // Used to validate that the delegate's auth handler was called

- (void)URLSession:(NSURLSession * _Nonnull)session
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

@end


@implementation TestNSURLSessionDelegateSessionDidReceiveChallenge

- (void)URLSession:(NSURLSession * _Nonnull)session
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    _wasAuthHandlerCalled = YES;
    [testExpectation fulfill];
}

@end
*/

// An NSURLSessionDelegate
@interface SessionDelegate : NSObject<NSURLSessionDelegate, NSURLAuthenticationChallengeSender>
@end
@implementation SessionDelegate

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    completionHandler(NSURLSessionAuthChallengeUseCredential, challenge.proposedCredential);
}

- (void)fakeMethod { }

- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}

- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}

- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}

@end

// An NSURLSession and Task delegate
@interface TaskAndSessionDelegate : SessionDelegate<NSURLSessionTaskDelegate>
@end
@implementation TaskAndSessionDelegate

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{ }

- (void)fakeMethod { }

@end

// An NSURLSessionTask delegate (only, no NSURLSessionDelegate methods)
@interface TaskDelegate : NSObject<NSURLSessionTaskDelegate> @end
@implementation TaskDelegate

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{ }

- (void)fakeMethod { }

@end

// A delegate that doesn't actually implement any of the optional handlers
@interface NoOptionalsDelegate : NSObject<NSURLSessionTaskDelegate> @end
@implementation NoOptionalsDelegate
- (void)fakeMethod { }
@end

#pragma mark - Test suite

@interface TSKNSURLSessionTests : XCTestCase

@end

@implementation TSKNSURLSessionTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

#pragma mark respondsToSelector override

- (void)test_respondsToSelector_sessionDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[SessionDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);

    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);

    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_taskDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[TaskDelegate new]];
    
    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_taskAndSessionDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[TaskAndSessionDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_noOptionalsDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[NoOptionalsDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

#pragma mark forwardToOriginalDelegateAuthenticationChallenge

// Test session delegate that implements @selector(URLSession:didReceiveChallenge:completionHandler:)
- (void)test_forwardToOriginalDelegateAuthenticationChallenge_implements
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[SessionDelegate new]];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    NSURLAuthenticationChallenge *challenge = [NSURLAuthenticationChallenge new];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"CallbackInvoked"];
    
    BOOL result = [proxy forwardToOriginalDelegateAuthenticationChallenge:challenge
                                                        completionHandler:^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential) {
                                                            [expectation fulfill];
                                                        } forSession:session];
    
    XCTAssertTrue(result);
    
    [self waitForExpectationsWithTimeout:5.0 handler:nil];
}

// Test task delegate that doesn't implement @selector(URLSession:didReceiveChallenge:completionHandler:)
- (void)test_forwardToOriginalDelegateAuthenticationChallenge_doesNotImplement
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:[TaskDelegate new]];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    NSURLAuthenticationChallenge *challenge = [NSURLAuthenticationChallenge new];
    
    BOOL result = [proxy forwardToOriginalDelegateAuthenticationChallenge:challenge
                                                        completionHandler:^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential) {
                                                            XCTFail(@"Should not be invoked");
                                                        } forSession:session];
    
    XCTAssertFalse(result);
}

#pragma mark common_URLSession:challenge:challenge:completionHandler:

- (void)test_common_URLSession_invalidAuthMethod_session
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate];
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@""
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:delegate];
    });
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengeUseCredential);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
}

- (void)test_common_URLSession_invalidAuthMethod_task
{
    TaskDelegate *delegate = [TaskDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate];
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@""
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodHTTPBasic];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:[SessionDelegate new]];
    });
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengePerformDefaultHandling);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
}

- (void)test_common_URLSession_session_pinFailed
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate];
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname"
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodServerTrust];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:delegate];
    });
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    [TrustKit initializeWithConfiguration:@{}];
    [TrustKit sharedInstance].pinningValidator = validator;
    
    OCMExpect([validator evaluateTrust:challenge.protectionSpace.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldBlockConnection);
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengeCancelAuthenticationChallenge);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
    
    [(id)validator stopMocking];
    [TrustKit sharedInstance].pinningValidator = [TSKPinningValidator new];
}

- (void)test_common_URLSession_session_pinSuccess
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate];
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname"
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodServerTrust];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:delegate];
    });
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    [TrustKit initializeWithConfiguration:@{}];
    [TrustKit sharedInstance].pinningValidator = validator;
    
    OCMExpect([validator evaluateTrust:challenge.protectionSpace.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengeUseCredential);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
    
    [(id)validator stopMocking];
    [TrustKit sharedInstance].pinningValidator = [TSKPinningValidator new];
}

#pragma mark URLSession:didReceiveChallenge:challenge:completionHandler:

- (void)test_urlSessionChallengeDelegate
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate]);
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname"
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodServerTrust];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:delegate];
    });
    
    TSKURLSessionAuthChallengeCallback completionHandler = ^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential) {};
    
    OCMExpect([proxy common_URLSession:session
                             challenge:challenge
                     completionHandler:completionHandler]).andDo(^(NSInvocation *i){});
    
    [proxy URLSession:session didReceiveChallenge:challenge completionHandler:completionHandler];
    
    OCMVerifyAll((id)proxy);
    [(id)proxy stopMocking];
}

#pragma mark URLSession:task:didReceiveChallenge:completionHandler:

- (void)test_urlSessionTaskChallengeDelegate
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLSessionDelegateProxy alloc] initWithDelegate:delegate]);
    
    NSURLSession *session = [NSURLSession new];
    NSURLAuthenticationChallenge *challenge = ({
        NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname"
                                                                            port:443
                                                                        protocol:@""
                                                                           realm:@""
                                                            authenticationMethod:NSURLAuthenticationMethodServerTrust];
        [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                   proposedCredential:nil
                                                 previousFailureCount:0
                                                      failureResponse:nil
                                                                error:nil
                                                               sender:delegate];
    });
    
    TSKURLSessionAuthChallengeCallback completionHandler = ^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential) {};
    
    OCMExpect([proxy common_URLSession:session
                             challenge:challenge
                     completionHandler:completionHandler]).andDo(^(NSInvocation *i){});
    
    [proxy URLSession:session
                 task:[NSURLSessionTask new]
  didReceiveChallenge:challenge
    completionHandler:completionHandler];
    
    OCMVerifyAll((id)proxy);
    [(id)proxy stopMocking];
}

@end

/*
#pragma mark Test suite
@interface TSKNSURLSessionTests : XCTestCase

@end

@implementation TSKNSURLSessionTests

- (void)setUp {
    [super setUp];
    [TrustKit resetConfiguration];
    [TSKNSURLSessionDelegateProxy resetLastTrustDecision];
    [[NSURLCache sharedURLCache] removeAllCachedResponses];
}

- (void)tearDown {
    [super tearDown];
}

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
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
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
    XCTAssert(([TSKNSURLSessionDelegateProxy getLastTrustDecision] == TSKTrustDecisionShouldBlockConnection), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
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
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://self-signed.badssl.com/"]];
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


// Tests a secure connection to https://self-signed.badssl.com with an invalid certificate chain and ensure that TrustKit is not disabling default certificate validation for domains that are not even pinned
- (void)testPinningValidationFailedChainNotTrustedAndNotPinned
{
    // This is not needed but to ensure TrustKit does get initialized
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKEnforcePinning : @NO,  // Do not enforce pinning to ensure default SSL validation is still enabled
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8=", // Leaf key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    id observerId = [[NSNotificationCenter defaultCenter] addObserverForName:kTSKValidationCompletedNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification * _Nonnull note) {
                                                                      // Ensure a validation notification was NOT posted
                                                                      XCTFail(@"kTSKValidationCompletedNotification should not have been posted");
                                                                  }];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSessionTaskDelegate"];
    TestNSURLSessionDelegate* delegate = [[TestNSURLSessionDelegate alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://self-signed.badssl.com/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error)
     {
         if (error)
         {
             NSLog(@"Timeout Error: %@", error);
         }
     }];
    XCTAssert(([TSKNSURLSessionDelegateProxy getLastTrustDecision] == TSKTrustDecisionDomainNotPinned), @"TrustKit accepted an invalid certificate");
    XCTAssertNotNil(delegate.lastError, @"TrustKit did not trigger an error");
    XCTAssertNil(delegate.lastResponse, @"TrustKit returned a response although pin validation failed");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


- (void)testPinningValidationSucceeded
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.datatheorem.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
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
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationNotedHostnameNotificationKey], @"www.datatheorem.com");
                                                                      XCTAssertEqualObjects(userInfo[kTSKValidationServerHostnameNotificationKey], @"www.datatheorem.com");
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationCertificateChainNotificationKey] count], (unsigned long)1);
                                                                      XCTAssertGreaterThan([userInfo[kTSKValidationDurationNotificationKey] doubleValue], 0);
                                                                      [notifReceivedExpectation fulfill];
                                                                  }];
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSession"];
    TestNSURLSessionDelegate *delegate = [[TestNSURLSessionDelegate alloc] initWithExpectation:expectation];
    
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
    
    // Run other NSURLSession methods that we swizzle to display a warning, to ensure they don't crash
    
    // Start a session with a nil delegate
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:nil
                                                     delegateQueue:nil];
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.google.com/"]];
    [task resume];
    
    // Start a session with +sessionWithConfiguration:
    NSURLSession *session2 = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
    NSURLSessionDataTask *task2 = [session2 dataTaskWithURL:[NSURL URLWithString:@"https://www.google.com/"]];
    [task2 resume];

    // Start a session with +sharedSession
    NSURLSession *session3 = [NSURLSession sharedSession];
    NSURLSessionDataTask *task3 = [session3 dataTaskWithURL:[NSURL URLWithString:@"https://www.yahoo.com/"]];
    [task3 resume];
}


// Ensure that if the original delegate has an auth handler, it also gets called when pinning validation succeed
// so that we don't disrupt the App's usual flow because of TrustKit's swizzling
- (void)testTaskDidReceiveChallengeGetsCalled
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.apple.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"gMxWOrX4PMQesK9qFNbYBxjBfjUvlkn/vN1n+L9lE5E=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
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
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSession"];
    TestNSURLSessionDelegateTaskDidReceiveChallenge *delegate = [[TestNSURLSessionDelegateTaskDidReceiveChallenge alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.apple.com/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
    XCTAssert(delegate.wasAuthHandlerCalled, @"TrustKit prevented the original delegate's auth handler from being called");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}


// Ensure that if the original delegate has an auth handler, it also gets called when pinning validation succeed
// so that we don't disrupt the App's usual flow because of TrustKit's swizzling
- (void)testSessionDidReceiveChallengeGetsCalled
{
    NSDictionary *trustKitConfig =
    @{
      kTSKSwizzleNetworkDelegates: @YES,
      kTSKPinnedDomains :
          @{
              @"www.fastmail.fm" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"5kJvNEMw0KjrCAu7eXY5HZdvyCS13BbA0VJG1RSP91w=", // CA key
                                              @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
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
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLSession"];
    TestNSURLSessionDelegateSessionDidReceiveChallenge *delegate = [[TestNSURLSessionDelegateSessionDidReceiveChallenge alloc] initWithExpectation:expectation];
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];
    
    NSURLSessionDataTask *task = [session dataTaskWithURL:[NSURL URLWithString:@"https://www.fastmail.fm/"]];
    [task resume];
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
    XCTAssert(delegate.wasAuthHandlerCalled, @"TrustKit prevented the original delegate's auth handler from being called");
    
    [[NSNotificationCenter defaultCenter] removeObserver:observerId];
}

@end
*/
