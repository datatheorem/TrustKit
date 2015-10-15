//
//  TSKNSURLSessionDelegateProxy.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import "TSKNSURLSessionDelegateProxy.h"
#import "RSSwizzle.h"
#import "TrustKit+Private.h"


// Useful for the tests
static TSKTrustDecision _lastTrustDecision = -1;


@implementation TSKNSURLSessionDelegateProxy


// Private methods used for tests
+(void)resetLastTrustDecision
{
    _lastTrustDecision = -1;;
}

+(TSKTrustDecision)getLastTrustDecision
{
    return _lastTrustDecision;
}


+ (void)swizzleNSURLSessionConstructors
{
    // Figure out NSURLSession's "real" class
    NSString *NSURLSessionClass;
    if (NSClassFromString(@"NSURLSession") != nil)
    {
        // iOS 8+
        NSURLSessionClass = @"NSURLSession";
    }
    else if (NSClassFromString(@"NSURLSession") != nil)
    {
        // Pre iOS 8, for some reason hooking NSURLSession doesn't work. We need to use the real/private class __NSCFURLSession
        NSURLSessionClass = @"__NSCFURLSession";
    }
    else
    {
        TSKLog(@"ERROR: Could not find NSURLSession's class");
        return;
    }
    
    // + sessionWithConfiguration:delegate:delegateQueue:
    RSSwizzleClassMethod(NSClassFromString(NSURLSessionClass),
                         @selector(sessionWithConfiguration:delegate:delegateQueue:),
                         RSSWReturnType(NSURLSession *),
                         RSSWArguments(NSURLSessionConfiguration * _Nonnull configuration, id _Nullable delegate, NSOperationQueue * _Nullable queue),
                         RSSWReplacement(
                                         {
                                             NSURLSession *session;
                                             
                                             if (delegate == nil)
                                             {
                                                 // Just display a warning
                                                 //TSKLog(@"WARNING: +sessionWithConfiguration:delegate:delegateQueue: was called with a nil delegate; TrustKit cannot enforce SSL pinning for any connection initiated by this session");
                                                 session = RSSWCallOriginal(configuration, delegate, queue);
                                             }
                                             
                                             // Do not swizzle TrustKit objects (such as the reporter)
                                             else if ([NSStringFromClass([delegate class]) hasPrefix:@"TSK"])
                                             {
                                                 session = RSSWCallOriginal(configuration, delegate, queue);
                                             }
                                             else
                                             {
                                                 // Replace the delegate with our own so we can intercept and handle authentication challenges
                                                 TSKNSURLSessionDelegateProxy *swizzledDelegate = [[TSKNSURLSessionDelegateProxy alloc]initWithDelegate:delegate];
                                                 session = RSSWCallOriginal(configuration, swizzledDelegate, queue);
                                             }
                                             
                                             return session;
                                         }));
    // Not hooking the following methods as they end up calling +sessionWithConfiguration:delegate:delegateQueue:
    // +sessionWithConfiguration:
    // +sharedSession
}



- (instancetype)initWithDelegate:(id)delegate
{
    self = [super init];
    if (self)
    {
        originalDelegate = delegate;
    }
    TSKLog(@"Proxy-ing NSURLSessionDelegate: %@", NSStringFromClass([delegate class]));
    _lastTrustDecision = -1;
    return self;
}


- (BOOL)respondsToSelector:(SEL)aSelector
{
    if (aSelector == @selector(URLSession:task:didReceiveChallenge:completionHandler:))
    {
        // For the task-level handler, mirror the delegate
        return [originalDelegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)];
    }
    else if (aSelector == @selector(URLSession:didReceiveChallenge:completionHandler:))
    {
        if ([originalDelegate respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)] == YES)
        {
            return YES;
        }
        else
        {
            if ([originalDelegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)] == NO)
            {
                // If the task-level handler is not implemented in the delegate, we need to implement the session-level handler
                // regardless of what the delegate implements, to ensure we get to handle auth challenges so we can do pinning validation
                return YES;
            }
            else
            {
                // Let the task-level handler handle auth challenges
                return NO;
            }
        }
    }
    else
    {
        // The delegate proxy should mirror the original delegate's methods so that it doesn't change the app flow
        return [originalDelegate respondsToSelector:aSelector];
    }
}


- (id)forwardingTargetForSelector:(SEL)sel
{
    // Forward messages to the original delegate if the proxy doesn't implement the method
    return originalDelegate;
}


-(BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                                      completionHandler:(void (^ _Nonnull) (NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential))completionHandler
                                             forSession:(NSURLSession * _Nonnull)session
{
    BOOL wasChallengeHandled = NO;
    
    // Can the original delegate handle this challenge ?
    if  ([originalDelegate respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)])
    {
        // Yes - forward the challenge to the original delegate
        wasChallengeHandled = YES;
        [originalDelegate URLSession:session didReceiveChallenge:challenge completionHandler:completionHandler];
    }
    return wasChallengeHandled;
}


- (void)URLSession:(NSURLSession * _Nonnull)session
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    BOOL wasChallengeHandled = NO;
    
    // For SSL pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        TSKTrustDecision trustDecision = TSKTrustDecisionShouldBlockConnection;
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
        
        // Check the trust object against the pinning policy
        trustDecision = [TSKPinningValidator evaluateTrust:serverTrust forHostname:serverHostname];
        _lastTrustDecision = trustDecision;
        if (trustDecision == TSKTrustDecisionShouldAllowConnection)
        {
            // Success - don't do anything and forward the challenge to the original delegate
            wasChallengeHandled = NO;
        }
        else if (trustDecision == TSKTrustDecisionDomainNotPinned)
        {
            if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge completionHandler:completionHandler forSession:session])
            {
                // The original delegate handled the challenge and performed SSL validation itself
                wasChallengeHandled = YES;
            }
            else
            {
                // The original delegate does not have authentication handlers for this challenge
                // We need to do the default validation ourselves to avoid disabling SSL validation for all non pinned domains
                TSKLog(@"Performing default certificate validation for %@", serverHostname);
                SecTrustResultType trustResult = 0;
                SecTrustEvaluate(serverTrust, &trustResult);
                if ((trustResult != kSecTrustResultUnspecified) && (trustResult != kSecTrustResultProceed))
                {
                    // Default SSL validation failed - block the connection
                    CFDictionaryRef evaluationDetails = SecTrustCopyResult(serverTrust);
                    TSKLog(@"Error: default SSL validation failed: %@", evaluationDetails);
                    CFRelease(evaluationDetails);
                    wasChallengeHandled = YES;
                    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
                }
            }
        }
        else
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    if (wasChallengeHandled == NO)
    {
        if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge completionHandler:completionHandler forSession:session] == NO)
        {
            // The original delegate could not handle the challenge; use the default handler
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        }
    }
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    BOOL wasChallengeHandled = NO;
    
    // For SSL pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        TSKTrustDecision trustDecision = TSKTrustDecisionShouldBlockConnection;
        
        // Check the trust object against the pinning policy
        trustDecision = [TSKPinningValidator evaluateTrust:challenge.protectionSpace.serverTrust
                                               forHostname:challenge.protectionSpace.host];
        _lastTrustDecision = trustDecision;
        if ((trustDecision == TSKTrustDecisionShouldAllowConnection) || (trustDecision == TSKTrustDecisionDomainNotPinned))
        {
            // Don't do anything and forward the challenge to the original delegate
            wasChallengeHandled = NO;
        }
        else
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    if (wasChallengeHandled == NO)
    {
        // If we're in this delegate method (and not URLSession:didReceiveChallenge:completionHandler:)
        // it means the delegate definitely implements the handler method so we can call it directly
        [originalDelegate URLSession:session task:task didReceiveChallenge:challenge completionHandler:completionHandler];
    }
}

@end
