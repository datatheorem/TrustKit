//
//  TSKSwizzlingTests.m
//  TrustKit
//
//  Created by Alban Diquet on 6/26/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

#import "../TrustKit/Swizzling/TSKNSURLConnectionDelegateProxy.m"
#import "../TrustKit/Swizzling/TSKNSURLSessionDelegateProxy.h"
#import <XCTest/XCTest.h>

@interface TSKSwizzlingTests : XCTestCase

@end

@interface TSKAppSessionDelegate : NSObject <NSURLSessionDelegate>
@end

@implementation TSKAppSessionDelegate
@end

/* Basic tests to ensure RSSwizzle does not trigger a crash because a method we are hooking has changed
 */
@implementation TSKSwizzlingTests

- (void)setUp {
    [super setUp];
}

- (void)tearDown {
    [super tearDown];
}

- (void)testNSURLSession {
    NSDictionary *trustKitConfig = @{
        kTSKPinnedDomains: @ {
            @"www.datatheorem.com": @ {
                kTSKEnforcePinning: @YES,
                kTSKPublicKeyHashes: @[
                    @"58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=", // CA key
                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                ]
            }
        }
    };

    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];

    [TSKNSURLSessionDelegateProxy swizzleNSURLSessionConstructors:trustKit];

    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:[[TSKAppSessionDelegate alloc] init]
                                                     delegateQueue:nil];
    XCTAssertTrue([session.delegate isKindOfClass:[TSKNSURLSessionDelegateProxy class]], @"An app delegate whose class name starts with TSK must still be proxied");
    [session invalidateAndCancel];
}

- (void)testNSURLConnection {
    NSDictionary *trustKitConfig = @{
        kTSKPinnedDomains: @ {
            @"www.datatheorem.com": @ {
                kTSKEnforcePinning: @YES,
                kTSKPublicKeyHashes: @[
                    @"58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=", // CA key
                    @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                ]
            }
        }
    };

    TrustKit *trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];

    [TSKNSURLConnectionDelegateProxy swizzleNSURLConnectionConstructors:trustKit];
}

@end
