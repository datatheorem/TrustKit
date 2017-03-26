//
//  TSKNSURLConnectionDelegateProxy.h
//  TrustKit
//
//  Created by Alban Diquet on 10/7/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface TSKNSURLConnectionDelegateProxy : NSObject<NSURLConnectionDelegate>

// Initalize our hooks
+ (void)swizzleNSURLConnectionConstructors;

- (instancetype _Nullable)initWithDelegate:(id)delegate;

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;

@end

NS_ASSUME_NONNULL_END
