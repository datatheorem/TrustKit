//
//  TSKReportsRateLimiterTests.m
//  TrustKit
//
//  Created by Adam Kaplan on 4/5/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "../TrustKit/Reporting/TSKPinFailureReport.h"
#import "../TrustKit/Reporting/TSKReportsRateLimiter.m"
#import "TSKCertificateUtils.h"

#import <OCMock/OCMock.h>

@interface TSKReportsRateLimiter (ExposeTests)
@property (nonatomic) NSDate *lastReportsCacheResetDate;
@end

@interface TSKReportsRateLimiterTests : XCTestCase
@property (nonatomic, readonly) TSKReportsRateLimiter *rateLimiter;
@property (nonatomic, readonly) SecTrustRef testTrust;
@property (nonatomic, readonly) NSArray<NSString *> *testCertificateChain;
@property (nonatomic, readonly) TSKPinFailureReport *testReport;
@end

@implementation TSKReportsRateLimiterTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    _rateLimiter = [TSKReportsRateLimiter new];
    
    SecCertificateRef rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    
    SecCertificateRef certChainArray[1] = { leafCertificate };
    SecCertificateRef trustStoreArray[1] = { rootCertificate };
    
    _testTrust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                      arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                               anchorCertificates:(const void **)trustStoreArray
                                                      arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    _testCertificateChain = convertTrustToPemArray(self.testTrust);
    
    // Create the pin validation failure report
    NSArray *certificateChain = convertTrustToPemArray(self.testTrust);
    NSArray *formattedPins = convertPinsToHpkpPins([NSSet setWithArray:@[[[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="
                                                                                                            options:(NSDataBase64DecodingOptions)0],
                                                                         [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
                                                                                                            options:(NSDataBase64DecodingOptions)0]]
                                                    ]);
    
    _testReport = [[TSKPinFailureReport alloc] initWithAppBundleId:@"test"
                                                        appVersion:@"1.2.3"
                                                       appPlatform:@"IOS"
                                                appPlatformVersion:@"9.0.0"
                                                       appVendorId:@"test"
                                                   trustkitVersion:@"4.3.2.1"
                                                          hostname:@"mail.example.com"
                                                              port:@443
                                                          dateTime:[NSDate dateWithTimeIntervalSinceReferenceDate:0]
                                                     notedHostname:@"example.com"
                                                 includeSubdomains:NO
                                                    enforcePinning:NO
                                         validatedCertificateChain:certificateChain
                                                         knownPins:formattedPins
                                                  validationResult:TSKTrustEvaluationFailedInvalidCertificateChain
                                                    expirationDate:[NSDate dateWithTimeIntervalSinceReferenceDate:0]];

}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

// Ensure a new report will be sent
- (void)test_noRateLimitOnFirstReport
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
}

// Ensure the same report will not be sent twice in a row
- (void)test_rateLimitDuplicateReport
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    XCTAssertTrue([self.rateLimiter shouldRateLimitReport:self.testReport], @"Failed to rate-limit a repeated report");
    // And sanity check, why not?
    XCTAssertTrue([self.rateLimiter shouldRateLimitReport:self.testReport], @"Failed to rate-limit a repeated report x2");
}

// Ensure the same report will not be sent twice in a row
- (void)test_rateLimitAllowDuplicateAfter24Hours
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    XCTAssertTrue([self.rateLimiter shouldRateLimitReport:self.testReport], @"Failed to rate-limit a repeated report");
    
    // Force update the cache timer to replicate a day passing, then re-run the tests
    self.rateLimiter.lastReportsCacheResetDate = [NSDate dateWithTimeIntervalSinceNow:-3601 * 24];
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a duplicate report after 24 hours");
    XCTAssertTrue([self.rateLimiter shouldRateLimitReport:self.testReport], @"Failed to rate-limit a repeated report");
}

// Hashing test: noted hostname
- (void)test_rateLimitHashing_notedHostname
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.notedHostname).andReturn(@"flargle.blargle.com");
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

// Hashing test: hostname
- (void)test_rateLimitHashing_hostname
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.hostname).andReturn(@"flargle.blargle.com");
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

// Hashing test: noted port
- (void)test_rateLimitHashing_port
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.port).andReturn(@9090);
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

// Hashing test: certificate chain
- (void)test_rateLimitHashing_validatedCertificateChain
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.validatedCertificateChain).andReturn(@[]);
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

// Hashing test: known pins
- (void)test_rateLimitHashing_knownPins
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.knownPins).andReturn(@[]);
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

// Hashing test: validation result
- (void)test_rateLimitHashing_validationResult
{
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:self.testReport], @"Wrongly rate-limited a new report");
    
    TSKPinFailureReport *mockReport = OCMPartialMock(self.testReport);
    OCMStub(mockReport.validationResult).andReturn(TSKTrustEvaluationErrorCouldNotGenerateSpkiHash);
    
    XCTAssertFalse([self.rateLimiter shouldRateLimitReport:mockReport], @"Wrongly rate-limited a new report");
    
    [(id)mockReport stopMocking];
}

@end
