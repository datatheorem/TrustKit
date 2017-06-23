//
//  TSKNSURLConnectionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/TrustKit.h"
#import "../TrustKit/TSKPinningValidator.h"
#import "../TrustKit/TSKPinningValidatorResult.h"
#import "../TrustKit/Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import <OCMock/OCMock.h>

@interface TSKNSURLConnectionDelegateProxy (TestSupport)
@property (nonatomic) TSKTrustEvaluationResult lastTrustDecision;
-(BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection;
@end

@interface TrustKit (TestSupport)
+ (void)resetConfiguration;
@end

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

@interface TSKNSURLConnectionTests : XCTestCase
@property (nonatomic) TrustKit *trustKit;
@end

@implementation TSKNSURLConnectionTests

- (void)setUp {
    [super setUp];
    _trustKit = [[TrustKit alloc] initWithConfiguration:@{ } identifier:@"test"];
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
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                   connectionDelegate:[TestModeADelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);

    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                   connectionDelegate:[TestModeBDelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
}

- (void)respondsToSelector_trueForOriginalMethods
{
    TSKNSURLConnectionDelegateProxy *proxy;
    
    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                   connectionDelegate:[TestModeADelegate new]];
    XCTAssertTrue([proxy respondsToSelector:@selector(fakeMethod)]);

    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                   connectionDelegate:[TestModeBDelegate new]];
    XCTAssertFalse([proxy respondsToSelector:@selector(fakeMethod)]);
}

- (void)test_respondsToSelector_falseForUnimplementedMethods
{
    TSKNSURLConnectionDelegateProxy *proxy;

    proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                   connectionDelegate:[TestModeADelegate new]];
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
    [(id)proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn];
    
    OCMVerifyAll((id)delegate);
    [(id)delegate stopMocking];
}

#pragma mark - connection:willSendRequestForAuthenticationChallenge:

- (void)test_connectionWillSendRequestForAuthenticationChallenge_notServerTrust
{
    TestModeADelegate *delegate = OCMStrictClassMock([TestModeADelegate class]);
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
    
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
    self.trustKit.pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                                   connectionDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMExpect([proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn]);
    OCMStub([proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge]).andForwardToRealObject();
    OCMExpect([delegate performDefaultHandlingForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}

- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustB_allow
{
    TestModeBDelegate *delegate = OCMPartialMock([TestModeBDelegate new]);
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    self.trustKit.pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                                   connectionDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMStub([proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge]).andForwardToRealObject();
    // Test that the forward method was called – that method was tested in it's own unit tests.
    OCMExpect([proxy forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:cnxn]).andReturn(NO);
    OCMExpect([delegate performDefaultHandlingForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}

// Test the block case: only need to test for one because the failure handling is identical
- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustB_block
{
    TestModeBDelegate *delegate = OCMPartialMock([TestModeBDelegate new]);
    
    TSKPinningValidator *validator = OCMStrictClassMock([TSKPinningValidator class]);
    self.trustKit.pinningValidator = validator;
    
    NSURLConnection *cnxn = [[NSURLConnection alloc] init];
    NSURLProtectionSpace *space = [[NSURLProtectionSpace alloc] initWithHost:@"hostname" port:0 protocol:nil realm:nil
                                                        authenticationMethod:NSURLAuthenticationMethodServerTrust];
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:space
                                                                                         proposedCredential:nil
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:delegate];
    
    TSKNSURLConnectionDelegateProxy *proxy = OCMPartialMock([[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                                   connectionDelegate:delegate]);
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldBlockConnection);
    OCMExpect([delegate cancelAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    OCMVerifyAll((id)proxy);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
    [(id)proxy stopMocking];
}

// TODO: add swizzling tests to ensure the above tested methods are properly invoked.

#pragma GCC diagnostic pop
@end
