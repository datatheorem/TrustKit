//
//  TSKNSURLConnectionDelegateProxy.m
//  TrustKit
//
//  Created by Alban Diquet on 10/7/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import "TSKNSURLConnectionDelegateProxy.h"
#import "TSKPinningValidator.h"
#import "TrustKit+Private.h"
#import "RSSwizzle.h"


static const void *swizzleOnceKey = &swizzleOnceKey;


@implementation TSKNSURLConnectionDelegateProxy

+ (void)swizzleNSURLConnectionConstructor
{
    // - initWithRequest:delegate:
    RSSwizzleInstanceMethod(NSClassFromString(@"NSURLConnection"),
                            @selector(initWithRequest:delegate:),
                            RSSWReturnType(NSURLConnection*),
                            RSSWArguments(NSURLRequest *request, id delegate),
                            RSSWReplacement(
                                            {
                                                // Replace the delegate with our own so we can intercept and handle authentication challenges
                                                TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc]initWithDelegate:delegate];
                                                NSURLConnection *connection = RSSWCallOriginal(request, swizzledDelegate);
                                                return connection;
                                            }), RSSwizzleModeOncePerClass, swizzleOnceKey);
    
    
    // - initWithRequest:delegate:startImmediately:
    RSSwizzleInstanceMethod(NSClassFromString(@"NSURLConnection"),
                            @selector(initWithRequest:delegate:startImmediately:),
                            RSSWReturnType(NSURLConnection*),
                            RSSWArguments(NSURLRequest *request, id delegate, BOOL startImmediately),
                            RSSWReplacement(
                                            {
                                                // Replace the delegate with our own so we can intercept and handle authentication challenges
                                                TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc]initWithDelegate:delegate];
                                                NSURLConnection *connection = RSSWCallOriginal(request, swizzledDelegate, startImmediately);
                                                return connection;
                                            }), RSSwizzleModeOncePerClass, swizzleOnceKey);
    
    
    // TODO: Add warning for constructors that do not have a delegate (ie. we can't protect these connections)
}


- (TSKNSURLConnectionDelegateProxy *)initWithDelegate:(id)delegate
{
    self = [super init];
    if (self)
    {
        originalDelegate = delegate;
    }
    TSKLog(@"Proxy-ing NSURLConnectionDelegate: %@", NSStringFromClass([delegate class]));
    return self;
}


- (BOOL)respondsToSelector:(SEL)aSelector
{
    if (aSelector == @selector(connection:willSendRequestForAuthenticationChallenge:))
    {
        // The swizzled delegate should always receive authentication challenges
        return YES;
    }
    else
    {
        // The swizzled delegate should mirror the original delegate's methods so that it doesn't change the app flow
        return [originalDelegate respondsToSelector:aSelector];
    }
}


- (id)forwardingTargetForSelector:(SEL)sel
{
    // Forward messages to the original delegate if the proxy doesn't implement the method
    return originalDelegate;
}


// NSURLConnection is deprecated in iOS 9
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
-(BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection
{
    BOOL wasChallengeHandled = NO;
    
    // Can the original delegate handle this challenge ?
    if  ([originalDelegate respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)])
    {
        // Yes - forward the challenge to the original delegate
        wasChallengeHandled = YES;
        [originalDelegate connection:connection willSendRequestForAuthenticationChallenge:challenge];
    }
    else if ([originalDelegate respondsToSelector:@selector(connection:canAuthenticateAgainstProtectionSpace:)])
    {
        if ([originalDelegate connection:connection canAuthenticateAgainstProtectionSpace:challenge.protectionSpace])
        {
            // Yes - forward the challenge to the original delegate
            wasChallengeHandled = YES;
            [originalDelegate connection:connection didReceiveAuthenticationChallenge:challenge];
        }
    }

    return wasChallengeHandled;
}
#pragma GCC diagnostic pop


- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    BOOL wasChallengeHandled = NO;
    TSKPinValidationResult result = TSKPinValidationResultFailed;
    
    // For pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
    
        // Check the trust object against the pinning policy
        result = [TSKPinningValidator evaluateTrust:serverTrust forHostname:serverHostname];
        if (result == TSKPinValidationResultSuccess)
        {
            // Success - don't do anything and forward the challenge to the original delegate
            wasChallengeHandled = NO;
        }
        else if (result == TSKPinValidationResultDomainNotPinned)
        {
            if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:connection])
            {
                // The original delegate handled the challenge and performed SSL validation itself
                wasChallengeHandled = YES;
            }
            else
            {
                // The original delegate does not have authentication handlers for this challenge
                // We need to do the default validation ourselves to avoid disabling SSL validation for all non pinned domains
                SecTrustResultType trustResult = 0;
                SecTrustEvaluate(serverTrust, &trustResult);
                if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
                {
                    // Default SSL validation failed - block the connection
                    CFDictionaryRef evaluationDetails = SecTrustCopyResult(serverTrust);
                    TSKLog(@"Error: default SSL validation failed: %@", evaluationDetails);
                    CFRelease(evaluationDetails);
                    wasChallengeHandled = YES;
                    [challenge.sender cancelAuthenticationChallenge:challenge];
                }
            }
        }
        else
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            [challenge.sender cancelAuthenticationChallenge:challenge];
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    if (wasChallengeHandled == NO)
    {
        if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:connection] == NO)
        {
            // The original delegate could not handle the challenge; use the default handler
            [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
        }
    }
}



@end
