//
//  TrustKitTests.m
//  TrustKitTests
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>
#import "TrustKit.h"

#include <dlfcn.h>

@interface TrustKitTests : XCTestCase

@end

@implementation TrustKitTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testPinConfiguration {
    [TKSettings setPublicKeyPins:@{
            @"www.datatheorem.com" : @[
                    @"0000000000000000000000000000000000000000000000000000000000000000"
            ]
    } shouldOverwrite:YES];

    XCTAssertNotNil([TKSettings publicKeyPins][@"www.datatheorem.com"], @"There was no pin found for www.datatheorem.com");
    XCTAssertEqual([TKSettings publicKeyPins][@"www.datatheorem.com"][0], @"0000000000000000000000000000000000000000000000000000000000000000", @"The hash key does not match the one that was setup");
}


@end
