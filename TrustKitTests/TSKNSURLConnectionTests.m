//
//  TSKNSURLConnectionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/public/TSKPinningValidator.h"
#import "../TrustKit/public/TSKPinningValidatorResult.h"
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
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-implementations"
- (BOOL)connection:(NSURLConnection *)connection canAuthenticateAgainstProtectionSpace:(NSURLProtectionSpace *)protectionSpace {
    return self.shouldAuthenticate;
}
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge { }
#pragma clang diagnostic pop

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
    _trustKit = [[TrustKit alloc] initWithConfiguration:@{ }];
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];

    // Ensure the proxy mirrors the methods of the delegate
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
    
    // In this case the challenge was seen as valid by TrustKit and then gets forwarded to the original delegate
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMExpect([delegate connection:cnxn willSendRequestForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
}

- (void)test_connectionWillSendRequestForAuthenticationChallenge_serverTrustB_allow_noDelegateMethod
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
    
    // Ensure the proxy forces the usage of connection:willSendRequestForAuthenticationChallenge: VS the legacy connection:canAuthenticateAgainstProtectionSpace:
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
    
    // The delegate is NOT able to handle this challenge
    delegate.shouldAuthenticate = NO;
    // In this case the challenge was seen as valid by TrustKit and then the default handler gets called since the delegate has no method
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMExpect([delegate performDefaultHandlingForAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
    
    // Ensure the proxy forces the usage of connection:willSendRequestForAuthenticationChallenge: VS the legacy connection:canAuthenticateAgainstProtectionSpace:
    XCTAssertTrue([proxy respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)]);
    
    // The delegate is able to handle this challenge
    delegate.shouldAuthenticate = YES;
    // In this case the challenge was seen as valid by TrustKit and then gets forwarded to the original delegate's connection:didReceiveAuthenticationChallenge: method
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldAllowConnection);
    OCMExpect([delegate connection:cnxn didReceiveAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
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
    
    TSKNSURLConnectionDelegateProxy *proxy = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:self.trustKit
                                                                                    connectionDelegate:delegate];
    
    OCMExpect([validator evaluateTrust:space.serverTrust forHostname:@"hostname"]).andReturn(TSKTrustDecisionShouldBlockConnection);
    
    // In this case the challenge is directly handled by the proxy and should cancel the connection
    OCMExpect([delegate cancelAuthenticationChallenge:challenge]);
    
    [proxy connection:cnxn willSendRequestForAuthenticationChallenge:challenge];
    
    OCMVerifyAll((id)delegate);
    OCMVerifyAll((id)validator);
    
    [(id)validator stopMocking];
    [(id)delegate stopMocking];
}

// TODO: add swizzling tests to ensure the above tested methods are properly invoked.

#pragma GCC diagnostic pop
@end
