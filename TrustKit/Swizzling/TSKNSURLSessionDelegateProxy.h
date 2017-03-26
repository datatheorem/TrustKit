//
//  TSKNSURLSessionDelegateProxy.h
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void(^TSKURLSessionAuthChallengeCallback)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential);

@interface TSKNSURLSessionDelegateProxy : NSObject

+ (void)swizzleNSURLSessionConstructors;

- (instancetype _Nullable)initWithDelegate:(id)delegate;

- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler;

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(TSKURLSessionAuthChallengeCallback)completionHandler;

@end

NS_ASSUME_NONNULL_END
