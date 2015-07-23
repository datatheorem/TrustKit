/*
 
 TSKReporterTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TSKSimpleReporter.h"
#import "TSKRateLimitingBackgroundReporter.h"
#import "TSKCertificateUtils.h"


@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests
{
    SecTrustRef _testTrust;
    SecCertificateRef _rootCertificate;
    SecCertificateRef _intermediateCertificate;
    SecCertificateRef _leafCertificate;
}


- (void)setUp {
    [super setUp];
    
    _rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    _intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodIntermediateCA"];
    _leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    
    _testTrust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                      arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                               anchorCertificates:(const void **)trustStoreArray
                                                      arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
}

- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_intermediateCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_testTrust);
    
    [super tearDown];
}

- (void)testSimpleReporter
{
    // Just try a simple valid case to see if we can post this to the server
    TSKSimpleReporter *reporter = [[TSKSimpleReporter alloc] init];
    
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                   reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_report"]]
                           includeSubdomains:YES
                                   knownPins:@[
                                               [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                               [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                               ]
                            validationResult:TSKPinValidationResultFailed];

    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

- (void)testSimpleBackgroundReporter
{
    // Just try a simple valid case to see if we can post this to the server
    TSKSimpleBackgroundReporter *reporter = [[TSKSimpleBackgroundReporter alloc] init];
    
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_report"]]
                           includeSubdomains:YES
                                   knownPins:@[
                                               [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                               [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                               ]
                            validationResult:TSKPinValidationResultFailed];
    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

- (void)testRateLimitingBackgroundReporter
{
    TSKRateLimitingBackgroundReporter *reporter = [[TSKRateLimitingBackgroundReporter alloc] init];
    
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_report"]]
                           includeSubdomains:YES
                                   knownPins:@[
                                               [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                               [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                               ]
                            validationResult:TSKPinValidationResultFailed];
    
    // The second report should be rate-limited
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       trust:_testTrust
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:@"http://127.0.0.1:8080/log_report"]]
                           includeSubdomains:YES
                                   knownPins:@[
                                               [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=" options:0],
                                               [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=" options:0],
                                               ]
                            validationResult:TSKPinValidationResultFailed];
    
    
    [NSThread sleepForTimeInterval:5.0];
    XCTAssert(YES, @"Pass");
}

@end
