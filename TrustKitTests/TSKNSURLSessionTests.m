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
@property (nonatomic) TrustKit *trustKit;
@end

@implementation TSKNSURLSessionTests

- (void)setUp {
    [super setUp];
    _trustKit = [[TrustKit alloc] initWithConfiguration:@{ } identifier:nil];
}

- (void)tearDown {
    [super tearDown];
}

#pragma mark respondsToSelector override

- (void)test_respondsToSelector_sessionDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[SessionDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);

    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);

    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_taskDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[TaskDelegate new]];
    
    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_taskAndSessionDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[TaskAndSessionDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

- (void)test_respondsToSelector_noOptionalsDelegate
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[NoOptionalsDelegate new]];
    
    XCTAssertTrue([proxy respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertFalse([proxy respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)]);
    
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);
    
    XCTAssertFalse([proxy respondsToSelector:NSSelectorFromString(@"unimplementedMethod")]);
}

#pragma mark forwardToOriginalDelegateAuthenticationChallenge

// Test session delegate that implements @selector(URLSession:didReceiveChallenge:completionHandler:)
- (void)test_forwardToOriginalDelegateAuthenticationChallenge_implements
{
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[SessionDelegate new]];
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
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:[TaskDelegate new]];
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
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:delegate];
    
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
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:delegate];
    
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
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:delegate];
    
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
    self.trustKit.pinningValidator = validator;
    
    OCMExpect([validator evaluateTrust:challenge.protectionSpace.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldBlockConnection);
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengeCancelAuthenticationChallenge);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
    
    [(id)validator stopMocking];
}

- (void)test_common_URLSession_session_pinSuccess
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                 sessionDelegate:delegate];
    
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
    self.trustKit.pinningValidator = validator;
    
    OCMExpect([validator evaluateTrust:challenge.protectionSpace.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    
    [proxy common_URLSession:session
                   challenge:challenge
           completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                               NSURLCredential *credential) {
               XCTAssertEqual(disposition, NSURLSessionAuthChallengeUseCredential);
               XCTAssertEqual(credential, challenge.proposedCredential);
           }];
    
    [(id)validator stopMocking];
}

#pragma mark URLSession:didReceiveChallenge:challenge:completionHandler:

- (void)test_urlSessionChallengeDelegate
{
    SessionDelegate *delegate = [SessionDelegate new];
    TSKNSURLSessionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                                sessionDelegate:delegate]);
    
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
    TSKNSURLSessionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                                sessionDelegate:delegate]);
    
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
