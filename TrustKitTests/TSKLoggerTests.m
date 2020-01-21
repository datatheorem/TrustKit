//
//  TSKLoggerTests.m
//  TrustKit
//
//  Created by Alban Diquet on 8/29/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/TSKLog.h"


@interface TSKLoggerTests : XCTestCase

@end

@implementation TSKLoggerTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testDefaultLoggerBlock
{
    TSKLog(@"test %@", @"test");
}


- (void)testSetLoggerBlock
{
    __block bool wasBlockCalled = false;
    void (^loggerBlock)(NSString *) = ^void(NSString *message)
    {
        XCTAssert(message, @"test test");
        wasBlockCalled = true;
    };
    
    [TrustKit setLoggerBlock:loggerBlock];
    TSKLog(@"test %@", @"test");
    XCTAssertTrue(wasBlockCalled);
}

@end
