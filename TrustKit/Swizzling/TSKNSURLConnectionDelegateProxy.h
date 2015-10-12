//
//  TSKNSURLConnectionDelegateProxy.h
//  TrustKit
//
//  Created by Alban Diquet on 10/7/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface TSKNSURLConnectionDelegateProxy : NSObject<NSURLConnectionDelegate>
{
    id<NSURLConnectionDelegate> originalDelegate; // The NSURLConnectionDelegate we're going to proxy
}

// Initalize our hooks
+ (void)swizzleNSURLConnectionConstructors;

- (instancetype)initWithDelegate:(id)delegate;

// Mirror the original delegate's list of implemented methods
- (BOOL)respondsToSelector:(SEL)aSelector ;

// Forward messages to the original delegate if the proxy doesn't implement the method
- (id)forwardingTargetForSelector:(SEL)sel;

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge;


@end
