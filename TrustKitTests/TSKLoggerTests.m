//
//  TSKLoggerTests.m
//  TrustKit
//
//  Created by Alban Diquet on 8/29/16.
//  Copyright © 2016 TrustKit. All rights reserved.
//

//#import <XCTest/XCTest.h>
//#import "../TrustKit/TrustKit.h"
//
//
//extern void _TSKLog(NSString *format, ...);
//
//@interface TSKLoggerTests : XCTestCase
//
//@end
//
//@implementation TSKLoggerTests
//
//- (void)testDefaultLoggerBlock
//{
//    _TSKLog(@"test %@", @"test");
//}
//
//
//- (void)testSetLoggerBlock
//{
//    __block bool wasBlockCalled = false;
//    void (^loggerBlock)(NSString *) = ^void(NSString *message)
//    {
//        XCTAssert(message, @"test test");
//        wasBlockCalled = true;
//    };
//
//    TrustKit *tk = [TrustKit new];
//    tk.loggerBlock = loggerBlock;
//    TSKLog(@"test %@", @"test");
//    XCTAssertTrue(wasBlockCalled);
//}
//
//- (void)testSetLoggerBlock_singleton
//{
//    __block bool wasBlockCalled = false;
//    void (^loggerBlock)(NSString *) = ^void(NSString *message)
//    {
//        XCTAssert(message, @"test test");
//        wasBlockCalled = true;
//    };
//    
//    [TrustKit setLoggerBlock:loggerBlock];
//    TSKLog(@"test %@", @"test");
//    XCTAssertTrue(wasBlockCalled);
//}
//
//@end
