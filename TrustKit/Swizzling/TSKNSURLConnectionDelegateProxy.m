//
//  TSKNSURLConnectionDelegateProxy.m
//  TrustKit
//
//  Created by Alban Diquet on 10/7/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import "TSKNSURLConnectionDelegateProxy.h"
#import "../TrustKit+Private.h"
#import "../Dependencies/RSSwizzle/RSSwizzle.h"



typedef void (^AsyncCompletionHandler)(NSURLResponse *response, NSData *data, NSError *connectionError);


@interface TSKNSURLConnectionDelegateProxy(Private)
-(BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection;
@end


@implementation TSKNSURLConnectionDelegateProxy


#pragma mark Private methods used for tests

static TSKTrustDecision _lastTrustDecision = (TSKTrustDecision)-1;

+(void)resetLastTrustDecision
{
    _lastTrustDecision = (TSKTrustDecision)-1;
}

+(TSKTrustDecision)getLastTrustDecision
{
    return _lastTrustDecision;
}


#pragma mark Public methods

+ (void)swizzleNSURLConnectionConstructors
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"
    // - initWithRequest:delegate:
    RSSwizzleInstanceMethod(NSClassFromString(@"NSURLConnection"),
                            @selector(initWithRequest:delegate:),
                            RSSWReturnType(NSURLConnection*),
                            RSSWArguments(NSURLRequest *request, id<NSURLConnectionDelegate> delegate),
                            RSSWReplacement(
                                            {
                                                NSURLConnection *connection;
                                                
                                                if ([NSStringFromClass([delegate class]) hasPrefix:@"TSK"])
                                                {
                                                    // Don't proxy ourselves
                                                    connection = RSSWCallOriginal(request, delegate);
                                                }
                                                else
                                                {
                                                    // Replace the delegate with our own so we can intercept and handle authentication challenges
                                                    TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc]initWithDelegate:delegate];
                                                     connection = RSSWCallOriginal(request, swizzledDelegate);
                                                }
                                                return connection;
                                            }), RSSwizzleModeAlways, NULL);
    
    
    
    // - initWithRequest:delegate:startImmediately:
    RSSwizzleInstanceMethod(NSClassFromString(@"NSURLConnection"),
                            @selector(initWithRequest:delegate:startImmediately:),
                            RSSWReturnType(NSURLConnection*),
                            RSSWArguments(NSURLRequest *request, id<NSURLConnectionDelegate> delegate, BOOL startImmediately),
                            RSSWReplacement(
                                            {
                                                NSURLConnection *connection;
                                                
                                                if ([NSStringFromClass([delegate class]) hasPrefix:@"TSK"])
                                                {
                                                    // Don't proxy ourselves
                                                    connection = RSSWCallOriginal(request, delegate, startImmediately);
                                                }
                                                else
                                                {
                                                    // Replace the delegate with our own so we can intercept and handle authentication challenges
                                                    TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc]initWithDelegate:delegate];
                                                    connection = RSSWCallOriginal(request, swizzledDelegate, startImmediately);
                                                }
                                                return connection;
                                            }), RSSwizzleModeAlways, NULL);
    
    
    // Not hooking + connectionWithRequest:delegate: as it ends up calling initWithRequest:delegate:
    
    // Log a warning for methods that do not have a delegate (ie. we can't protect these connections)
    // + sendAsynchronousRequest:queue:completionHandler:
    
    RSSwizzleClassMethod(NSClassFromString(@"NSURLConnection"),
                         @selector(sendAsynchronousRequest:queue:completionHandler:),
                         RSSWReturnType(void),
                         RSSWArguments(NSURLRequest *request, NSOperationQueue *queue, AsyncCompletionHandler handler),
                         RSSWReplacement(
                                         {
                                             // Just display a warning
                                             TSKLog(@"WARNING: +sendAsynchronousRequest:queue:completionHandler: was called to connect to %@. This method does not expose a delegate argument for handling authentication challenges; TrustKit cannot enforce SSL pinning for these connections", [[request URL]host]);
                                             RSSWCallOriginal(request, queue, handler);
                                         }));
     
    
    // + sendSynchronousRequest:returningResponse:error:
    RSSwizzleClassMethod(NSClassFromString(@"NSURLConnection"),
                         @selector(sendSynchronousRequest:returningResponse:error:),
                         RSSWReturnType(NSData *),
                         RSSWArguments(NSURLRequest *request, NSURLResponse * _Nullable *response, NSError * _Nullable *error),
                         RSSWReplacement(
                                         {
                                             // Just display a warning
                                             TSKLog(@"WARNING: +sendSynchronousRequest:returningResponse:error: was called to connect to %@. This method does not expose a delegate argument for handling authentication challenges; TrustKit cannot enforce SSL pinning for these connections", [[request URL]host]);
                                             NSData *data = RSSWCallOriginal(request, response, error);
                                             return data;
                                         }));
#pragma clang diagnostic pop
}


- (instancetype)initWithDelegate:(id)delegate
{
    self = [super init];
    if (self)
    {
        originalDelegate = delegate;
    }
    TSKLog(@"Proxy-ing NSURLConnectionDelegate: %@", NSStringFromClass([delegate class]));
    return self;
}


#pragma mark Delegate methods

- (BOOL)respondsToSelector:(SEL)aSelector
{
    if (aSelector == @selector(connection:willSendRequestForAuthenticationChallenge:))
    {
        // The delegate proxy should always receive authentication challenges
        return YES;
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
    
    // For SSL pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        TSKTrustDecision trustDecision = TSKTrustDecisionShouldBlockConnection;
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
    
        // Check the trust object against the pinning policy
        trustDecision = [TSKPinningValidator evaluateTrust:serverTrust forHostname:serverHostname];
        _lastTrustDecision = trustDecision;
        if (trustDecision == TSKTrustDecisionShouldBlockConnection)
        {
            // Pinning validation failed - block the connection
            wasChallengeHandled = YES;
            [challenge.sender cancelAuthenticationChallenge:challenge];
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    if (wasChallengeHandled == NO)
    {
        // We will also get here if the pinning validation succeeded or the domain was not pinned
        if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:connection] == NO)
        {
            // The original delegate could not handle the challenge; use the default handler
            [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
        }
    }
}


@end
