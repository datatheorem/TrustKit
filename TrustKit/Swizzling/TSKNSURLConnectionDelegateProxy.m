/*
 
 TSKNSURLConnectionDelegateProxy.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKNSURLConnectionDelegateProxy.h"
#import "../public/TrustKit.h"
#import "../TSKLog.h"
#import "../public/TSKTrustDecision.h"
#import "../public/TSKPinningValidator.h"
#import "../Dependencies/RSSwizzle/RSSwizzle.h"

typedef void (^AsyncCompletionHandler)(NSURLResponse *response, NSData *data, NSError *connectionError);

@interface TSKNSURLConnectionDelegateProxy ()
@property (nonatomic) id<NSURLConnectionDelegate> originalDelegate; // The NSURLConnectionDelegate we're going to proxy
@property (nonatomic) TrustKit *trustKit;
@end

@implementation TSKNSURLConnectionDelegateProxy

#pragma mark Public methods

+ (void)swizzleNSURLConnectionConstructors:(TrustKit *)trustKit
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
                                                    TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:trustKit
                                                                                                                                               connectionDelegate:delegate];
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
                                                    TSKNSURLConnectionDelegateProxy *swizzledDelegate = [[TSKNSURLConnectionDelegateProxy alloc] initWithTrustKit:trustKit
                                                                                                                                               connectionDelegate:delegate];
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


#pragma mark Instance Constructors

- (instancetype)initWithTrustKit:(TrustKit *)trustKit connectionDelegate:(id<NSURLConnectionDelegate>)delegate
{
    self = [super init];
    if (self)
    {
        _originalDelegate = delegate;
        _trustKit = trustKit;
    }
    TSKLog(@"Proxy-ing NSURLConnectionDelegate: %@", NSStringFromClass([delegate class]));
    return self;
}

#pragma mark NSObject overrides

- (BOOL)respondsToSelector:(SEL)aSelector
{
    if (aSelector == @selector(connection:willSendRequestForAuthenticationChallenge:))
    {
        // The delegate proxy should always receive authentication challenges
        // This will disrupt the delegate flow for (old) delegates that use the connection:didReceiveAuthenticationChallenge: method
        return YES;
    }
    else
    {
        // The delegate proxy should mirror the original delegate's methods so that it doesn't change the app flow
        return [_originalDelegate respondsToSelector:aSelector];
    }
}


- (id)forwardingTargetForSelector:(SEL)sel
{
    return _originalDelegate;
}


#pragma mark Instance methods

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations" // NSURLConnection is deprecated in iOS 9
- (BOOL)forwardToOriginalDelegateAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection
{
    // Can the original delegate handle this challenge ?
    if  ([_originalDelegate respondsToSelector:@selector(connection:willSendRequestForAuthenticationChallenge:)])
    {
        // Yes - forward the challenge to the original delegate
        [_originalDelegate connection:connection willSendRequestForAuthenticationChallenge:challenge];
        return YES;
    }
    
    if ([_originalDelegate respondsToSelector:@selector(connection:canAuthenticateAgainstProtectionSpace:)]
        && [_originalDelegate connection:connection canAuthenticateAgainstProtectionSpace:challenge.protectionSpace])
    {
        // Yes - forward the challenge to the original delegate
        [_originalDelegate connection:connection didReceiveAuthenticationChallenge:challenge];
        return YES;
    }

    return NO;
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    // For SSL pinning we only care about server authentication
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust])
    {
        SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
        NSString *serverHostname = challenge.protectionSpace.host;
    
        // Check the trust object against the pinning policy
        TSKTrustDecision trustDecision = [self.trustKit.pinningValidator evaluateTrust:serverTrust
                                                                           forHostname:serverHostname];
        if (trustDecision == TSKTrustDecisionShouldBlockConnection)
        {
            // Pinning validation failed - block the connection
            [challenge.sender cancelAuthenticationChallenge:challenge];
            return;
        }
    }
    
    // Forward all challenges (including client auth challenges) to the original delegate
    // We will also get here if the pinning validation succeeded or the domain was not pinned
    if ([self forwardToOriginalDelegateAuthenticationChallenge:challenge forConnection:connection] == NO)
    {
        // The original delegate could not handle the challenge; use the default handler
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}
#pragma GCC diagnostic pop

@end
