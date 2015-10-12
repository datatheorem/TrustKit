//
//  TSKNSURLSessionDelegateProxy.h
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface TSKNSURLSessionDelegateProxy : NSObject
{
    id<NSURLSessionDelegate, NSURLSessionTaskDelegate> originalDelegate; // The NSURLSessionDelegate we're going to proxy
}

+ (void)swizzleNSURLSessionConstructors;

- (_Nullable instancetype)initWithDelegate:(_Nonnull id)delegate;

// Mirror the original delegate's list of implemented methods
- (BOOL)respondsToSelector:(_Nonnull SEL)aSelector;

// Forward messages to the original delegate if the proxy doesn't implement the method
- (_Nonnull id)forwardingTargetForSelector:(_Nonnull SEL)sel;

- (void)URLSession:(NSURLSession * _Nonnull)session
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didReceiveChallenge:(NSURLAuthenticationChallenge * _Nonnull)challenge
 completionHandler:(void (^ _Nonnull)(NSURLSessionAuthChallengeDisposition disposition,
                                      NSURLCredential * _Nullable credential))completionHandler;

@end
