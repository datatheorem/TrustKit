/*
 
 TSKNSURLSessionDelegateProxy.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

NS_ASSUME_NONNULL_BEGIN

@class TrustKit;

typedef void(^TSKURLSessionAuthChallengeCallback)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential);

@interface TSKNSURLSessionDelegateProxy : NSObject

+ (void)swizzleNSURLSessionConstructors:(TrustKit *)trustKit;

- (instancetype)init NS_UNAVAILABLE;

- (instancetype _Nullable)initWithTrustKit:(TrustKit *)trustKit sessionDelegate:(id<NSURLSessionDelegate>)delegate NS_DESIGNATED_INITIALIZER;

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler;

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler;

// Forward messages to the original delegate if the proxy doesn't implement the method
- (id)forwardingTargetForSelector:(SEL)sel;

@end

NS_ASSUME_NONNULL_END
