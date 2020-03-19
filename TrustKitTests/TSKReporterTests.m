/*
 
 TSKReporterTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>

#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/public/TSKTrustKitConfig.h"

#import "../TrustKit/public/TSKPinningValidatorResult.h"
#import "../TrustKit/TSKPinningValidator_Private.h"
#import "../TrustKit/Reporting/TSKBackgroundReporter.h"
#import "../TrustKit/Reporting/TSKPinFailureReport.h"
#import "../TrustKit/Reporting/reporting_utils.h"

#import <OCMock/OCMock.h>
#import "../TrustKit/Reporting/vendor_identifier.h"
#import "TSKCertificateUtils.h"

#pragma mark Test suite

@interface TrustKit (TestSupport)
@property (nonatomic) TSKBackgroundReporter *pinFailureReporter;
@property (nonatomic, readonly, nullable) NSDictionary *configuration;

- (void)sendValidationReport:(TSKPinningValidatorResult *)result notedHostname:(NSString *)notedHostname pinningPolicy:(NSDictionary<TSKDomainConfigurationKey, id> *)notedHostnamePinningPolicy;
@end


static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";


@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests
{
    TrustKit *_trustKit;
    //TSKPinFailureReport *_testReporter;
    SecTrustRef _testTrust;
    SecCertificateRef _rootCertificate;
    SecCertificateRef _leafCertificate;
    NSArray<NSString *> *_testCertificateChain;
}


- (void)setUp {
    [super setUp];
    
    _rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    _leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    
    SecCertificateRef certChainArray[1] = { _leafCertificate };
    SecCertificateRef trustStoreArray[1] = { _rootCertificate };
    
    _testTrust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                      arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                               anchorCertificates:(const void **)trustStoreArray
                                                      arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    _testCertificateChain = convertTrustToPemArray(_testTrust);
}

- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_testTrust);
    _trustKit = nil;
    //_testReporter = nil;
    
    [super tearDown];
}

// NOTE: this is more of a test of TrustKit.m
- (void)testSendReportFromValidationReport
{
    // Ensure that a pin validation notification triggers the upload of a report if the validation failed
    // Initialize TrustKit so the reporter block is ready to receive notifications
    NSString *expirationDateStr = @"2019-01-01";
    NSDictionary *trustKitConfig =
    @{kTSKSwizzleNetworkDelegates: @NO,
      kTSKPinnedDomains :
          @{
              @"www.test.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKExpirationDate : expirationDateStr,
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    
    _trustKit = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    // Expect a report to be sent out when a notification is posted
    NSSet *knownPins = [NSSet setWithArray:@[[[NSData alloc]initWithBase64EncodedString:@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                                                                                options:(NSDataBase64DecodingOptions)0],
                                             [[NSData alloc]initWithBase64EncodedString:@"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                                                                                options:(NSDataBase64DecodingOptions)0]]];
    
    
    NSDateFormatter *dateFormat = [[NSDateFormatter alloc] init];
    dateFormat.dateFormat = @"yyyy-MM-dd";
    dateFormat.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
    NSDate *expirationDate = [dateFormat dateFromString:expirationDateStr];
    
    TSKPinningValidatorResult *res;
    
    // TEST FAILURE
    // Setup mocking of the reporter
    id pinReporterMock = OCMClassMock([TSKBackgroundReporter class]);
    _trustKit.pinFailureReporter = pinReporterMock;
    
    OCMExpect([pinReporterMock pinValidationFailedForHostname:@"www.test.com"
                                                         port:nil
                                             certificateChain:_testCertificateChain
                                                notedHostname:@"www.test.com"
                                                   reportURIs:@[[NSURL URLWithString:@"https://overmind.datatheorem.com/trustkit/report"]]
                                            includeSubdomains:NO
                                               enforcePinning:YES
                                                    knownPins:knownPins
                                             validationResult:TSKTrustEvaluationErrorCouldNotGenerateSpkiHash
                                               expirationDate:expirationDate]);
    
    res = [[TSKPinningValidatorResult alloc] initWithServerHostname:@"www.test.com"
                                                        serverTrust:_testTrust
                                                   validationResult:TSKTrustEvaluationErrorCouldNotGenerateSpkiHash
                                                 finalTrustDecision:TSKTrustDecisionShouldBlockConnection
                                                 validationDuration:1.0];
    [_trustKit sendValidationReport:res notedHostname:@"www.test.com" pinningPolicy:_trustKit.configuration[kTSKPinnedDomains][@"www.test.com"]];
    
    // Ensure that the reporter was called
    [pinReporterMock verify];
    
    [pinReporterMock stopMocking];
    _trustKit.pinFailureReporter = nil;
    
    // TEST CA SUCCESS
    // Send a notification for a successful validation and ensure no report gets sent
    pinReporterMock = OCMClassMock([TSKBackgroundReporter class]);
    _trustKit.pinFailureReporter = pinReporterMock;
    
    res = [[TSKPinningValidatorResult alloc] initWithServerHostname:@"www.test.com"
                                                        serverTrust:_testTrust
                                                   validationResult:TSKTrustEvaluationSuccess
                                                 finalTrustDecision:TSKTrustDecisionShouldAllowConnection
                                                 validationDuration:1.0];

    // Ensure that the reporter was NOT called
    [_trustKit sendValidationReport:res notedHostname:@"www.test.com" pinningPolicy:_trustKit.configuration[kTSKPinnedDomains][@"www.test.com"]];
    [pinReporterMock verify];
    
    [pinReporterMock stopMocking];
    _trustKit.pinFailureReporter = nil;
    
#if !TARGET_OS_IPHONE
    // TEST USER-DEFINED SUCCESS
    // Send a notification for a successful validation and ensure no report gets sent
    pinReporterMock = OCMClassMock([TSKBackgroundReporter class]);
    _trustKit.pinFailureReporter = pinReporterMock;
    
    res = [[TSKPinningValidatorResult alloc] initWithServerHostname:@"www.test.com"
                                                        serverTrust:_testTrust
                                                   validationResult:TSKTrustEvaluationFailedUserDefinedTrustAnchor
                                                 finalTrustDecision:TSKTrustDecisionShouldAllowConnection
                                                 validationDuration:1.0];
    
    // Ensure that the reporter was NOT called
    [_trustKit sendValidationReport:res notedHostname:@"www.test.com" pinningPolicy:_trustKit.configuration[kTSKPinnedDomains][@"www.test.com"]];
    [pinReporterMock verify];
    [pinReporterMock stopMocking];
    pinReporterMock = nil;
#endif
}


- (void)testReporter
{
    // Just try a simple valid case to see if we can post this to the default report URL
    TSKBackgroundReporter *reporter = [[TSKBackgroundReporter alloc] initAndRateLimitReports:NO
                                                                   sharedContainerIdentifier:nil];
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                            certificateChain:_testCertificateChain
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:kTSKDefaultReportUri]]
                           includeSubdomains:YES
                              enforcePinning:YES
                                   knownPins:[NSSet setWithArray:@[
                                                                   [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="
                                                                                                      options:(NSDataBase64DecodingOptions)0],
                                                                   [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
                                                                                                      options:(NSDataBase64DecodingOptions)0]]]
                            validationResult:TSKTrustEvaluationFailedNoMatchingPin
                              expirationDate:[NSDate date]];
    
    [NSThread sleepForTimeInterval:0.1];
}

- (void)testReporterNilExpirationDate
{
    // Just try a simple valid case to see if we can post this to the default report URL
    TSKBackgroundReporter *reporter = [[TSKBackgroundReporter alloc] initAndRateLimitReports:NO
                                                                   sharedContainerIdentifier:nil];
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                            certificateChain:_testCertificateChain
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:kTSKDefaultReportUri]]
                           includeSubdomains:YES
                              enforcePinning:YES
                                   knownPins:[NSSet setWithArray:@[
                                                                   [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="
                                                                                                      options:(NSDataBase64DecodingOptions)0],
                                                                   [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
                                                                                                      options:(NSDataBase64DecodingOptions)0]]]
                            validationResult:TSKTrustEvaluationFailedNoMatchingPin
                              expirationDate:nil];
    
    [NSThread sleepForTimeInterval:0.1];
}

- (void)testIdentifierForVendor
{
    NSString *idfv = identifier_for_vendor();
    XCTAssertNotNil(idfv);
}

@end
