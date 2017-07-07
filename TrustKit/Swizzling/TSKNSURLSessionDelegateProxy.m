//
//  TSKNSURLSessionDelegateProxy.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import "TSKNSURLSessionDelegateProxy.h"
#import "../TrustKit.h"
#import "../TSKLog.h"
#import "../TSKTrustDecision.h"
#import "../TSKPinningValidator.h"
#import "../Dependencies/RSSwizzle/RSSwizzle.h"

@interface TSKNSURLSessionDelegateProxy ()
/* The NSURLSessionDelegate we're going to proxy */
@property (nonatomic) id<NSURLSessionDelegate> originalDelegate;
@property (nonatomic) TrustKit *trustKit;
@end

@implementation TSKNSURLSessionDelegateProxy

#pragma mark Public methods

+ (void)swizzleNSURLSessionConstructors:(TrustKit *)trustKit
{
    // + sessionWithConfiguration:delegate:delegateQueue:
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
    RSSwizzleClassMethod(NSURLSession.class,
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
                                                 TSKNSURLSessionDelegateProxy *swizzledDelegate = [[TSKNSURLSessionDelegateProxy alloc] initWithTrustKit:trustKit
                                                                                                                                         sessionDelegate:delegate];
                                                 session = RSSWCallOriginal(configuration, swizzledDelegate, queue);
                                             }

                                             return session;
                                         }));
    // Not hooking the following methods as they end up calling +sessionWithConfiguration:delegate:delegateQueue:
    // +sessionWithConfiguration:
    // +sharedSession
#pragma clang diagnostic pop
}

- (instancetype _Nullable)initWithTrustKit:(TrustKit *)trustKit sessionDelegate:(id<NSURLSessionDelegate>)delegate
{
    NSParameterAssert(delegate);
    
    self = [super init];
    if (self)
    {
        _originalDelegate = delegate;
        _trustKit = trustKit;
    }
    TSKLog(@"Proxy-ing NSURLSessionDelegate: %@", NSStringFromClass([delegate class]));
    return self;
}

#pragma mark Delegate methods

- (BOOL)respondsToSelector:(SEL)aSelector
{
    if (aSelector == @selector(URLSession:task:didReceiveChallenge:completionHandler:))
    {
        // For the task-level handler, mirror the delegate
        return [_originalDelegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)];
    }
    else if (aSelector == @selector(URLSession:didReceiveChallenge:completionHandler:))
    {
        if ([_originalDelegate respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)] == YES)
        {
            return YES;
        }
        else if ([_originalDelegate respondsToSelector:@selector(URLSession:task:didReceiveChallenge:completionHandler:)] == NO)
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
    else
    {
        // The delegate proxy should mirror the original delegate's methods so that it doesn't change the app flow
        return [_originalDelegate respondsToSelector:aSelector];
    }
}

- (BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
                                       completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler
                                              forSession:(NSURLSession * _Nonnull)session
{
    // Can the original delegate handle this challenge ?
    if  ([_originalDelegate respondsToSelector:@selector(URLSession:didReceiveChallenge:completionHandler:)])
    {
        // Yes - forward the challenge to the original delegate
        [_originalDelegate URLSession:session didReceiveChallenge:challenge completionHandler:completionHandler];
        return YES;
    }
    return NO;
}

- (void)common_URLSession:(NSURLSession * _Nonnull)session
                challenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
        completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                             NSURLCredential * _Nullable credential))completionHandler
{
    // For SSL pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        // Check the trust object against the pinning policy
        TSKTrustDecision trustDecision = [self.trustKit.pinningValidator evaluateTrust:challenge.protectionSpace.serverTrust
                                                                           forHostname:challenge.protectionSpace.host];
        if (trustDecision == TSKTrustDecisionShouldBlockConnection)
        {
            // Pinning validation failed - block the connection
            completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
            return; // Challenge handled (blocked), stop here!
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    // We will also get here if the pinning validation succeeded or the domain was not pinned
    if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge completionHandler:completionHandler forSession:session] == NO)
    {
        // The original delegate could not handle the challenge; use the default handler
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}

- (void)URLSession:(NSURLSession * _Nonnull)session
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler
{
    [self common_URLSession:session challenge:challenge completionHandler:completionHandler];
}

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler
{
    [self common_URLSession:session challenge:challenge completionHandler:completionHandler];
}

@end
