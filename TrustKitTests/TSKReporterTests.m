//
//  TSKReporterTests.m
//  TrustKit
//
//  Created by Angela Chow on 4/29/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TSKSimpleReporter.h"
#import "TSKSimpleBackgroundReporter.h"

@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests

SecTrustRef _testTrust;
SecCertificateRef _rootCertificate;
SecCertificateRef _chainCertificate;
SecCertificateRef _leafCertificate;
SecPolicyRef _policy;


- (void)setUp {
    [super setUp];
    
    CFDataRef rootData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"ca.cert" ofType:@"der"]];
    _rootCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, rootData);
    CFRelease(rootData);

    CFDataRef chainData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"ca-chain.cert" ofType:@"der"]];
    _chainCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, chainData);
    CFRelease(chainData);
    
    CFDataRef leafData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"www.good.com.cert" ofType:@"der"]];
    _leafCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, leafData);
    CFRelease(leafData);
    
    CFStringRef hostname = CFSTR("www.good.com");
    _policy = SecPolicyCreateSSL(true, hostname);
    
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    _testTrust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
}

- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_chainCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_policy);
    CFRelease(_testTrust);
    
    [super tearDown];
}

// Helper methods for cleaner testing code
- (SecTrustRef)_createTrustWithCertificates:(const void **)certArray arrayLength:(NSInteger)certArrayLength anchorCertificates:(const void **)anchorCertificates arrayLength:(NSInteger)anchorArrayLength
{
    CFArrayRef certs = CFArrayCreate(NULL, (const void **)certArray, certArrayLength, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **)anchorCertificates, anchorArrayLength, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    
    return trust;
}

- (void)testSimpleReporter {
    
    //just try a simple valid case to see if we can post this to the server
    TSKSimpleReporter *reporter = [[TSKSimpleReporter alloc] initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                   reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_csp_report"]]
                           includeSubdomains:YES
                                   knownPins:[NSArray arrayWithObjects:
                                              [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                              [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                              nil]];

    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

- (void)testSimpleBackgroundReporter {
    
    //just try a simple valid case to see if we can post this to the server
    TSKSimpleBackgroundReporter *reporter = [[TSKSimpleBackgroundReporter alloc] initWithAppBundleId:@"com.example.ABC" appVersion:@"1.0"];
    
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                   reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_csp_report"]]
                           includeSubdomains:YES
                                   knownPins:[NSArray arrayWithObjects:
                                              [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                              [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                              nil]];
    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}


- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
