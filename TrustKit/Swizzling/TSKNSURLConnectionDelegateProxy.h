/*
 
 TSKNSURLConnectionDelegateProxy.h
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

@interface TSKNSURLConnectionDelegateProxy : NSObject<NSURLConnectionDelegate>

// Initalize our hooks
+ (void)swizzleNSURLConnectionConstructors:(TrustKit *)trustKit;

- (instancetype)init NS_UNAVAILABLE;

- (instancetype _Nullable)initWithTrustKit:(TrustKit *)trustKit connectionDelegate:(id<NSURLConnectionDelegate> _Nullable)delegate NS_DESIGNATED_INITIALIZER;

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

// Forward messages to the original delegate if the proxy doesn't implement the method
- (id)forwardingTargetForSelector:(SEL)sel;

@end

NS_ASSUME_NONNULL_END
