//
//  TSKReporterTests.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TSKSimpleReporter.h"

@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSimpleReporter {
    
    //just try a simple valid case to see if we can post this to the server
    TSKSimpleReporter *reporter = [[TSKSimpleReporter alloc] init];
    
    [reporter initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    [reporter pinValidationFailed:@"example.com"
                   serverHostname:@"mail.example.com"
                       serverPort:[NSNumber numberWithInt:443]
                     reportingURL:@"http://localhost:3000"
                includeSubdomains:YES
                 certificateChain:[NSArray arrayWithObjects:
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIEBDCCAuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT"
                                   "HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto"
                                   "WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6"
                                   "yuGnBXj8ytqU0CwIPX4WecigUCAkVDNx"
                                   "-----END CERTIFICATE-----",
                                   @"-----BEGIN CERTIFICATE-----"
                                   "MIIABCDEFuygAwIBAgIDAjppMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVT"
                                   "HFa9llF7b1cq26KqltyMdMKVvvBulRP/F/A8rLIQjcxz++iPAsbw+zOzlTvjwsto"
                                   "WHPbqCRiOwY1nQ2pM714A5AuTHhdUDqB1O6gyHA43LL5Z/qHQF1hwFGPa4NrzQU6"
                                   "yuGnBXj8ytqU0CwIPX4WecigUCAkVDEF"
                                   "-----END CERTIFICATE-----",
                                   nil]
                     expectedPins:[NSArray arrayWithObjects:
                                   @"pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"",
                                   @"pin-sha256=\"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=\"",
                                   nil]];
    
    XCTAssert(YES, @"Pass");
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
