/*
 
 TSKReporterTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TSKBackgroundReporter.h"
#import "TSKPinFailureReport.h"
#import "TSKCertificateUtils.h"
#import "reporting_utils.h"
#import "TSKReportsRateLimiter.h"
#import "TrustKit+Private.h"
#import <OCMock/OCMock.h>


#if !TARGET_OS_IPHONE
#import "osx_vendor_id.h"
#endif

#pragma mark Test suite

@interface TSKReporterTests : XCTestCase

@end

@implementation TSKReporterTests
{
    SecTrustRef _testTrust;
    SecCertificateRef _rootCertificate;
    SecCertificateRef _intermediateCertificate;
    SecCertificateRef _leafCertificate;
    NSArray<NSString *> *_testCertificateChain;
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
    _testCertificateChain = convertTrustToPemArray(_testTrust);
}

- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_intermediateCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_testTrust);
    
    [super tearDown];
}

- (void)testSendReportFromNotificationBlock
{
    // Ensure that a pin validation notification triggers the upload of a report if the validation failed
    // Initialize TrustKit so the reporter block is ready to receive notifications
    NSDictionary *trustKitConfig =
    @{kTSKSwizzleNetworkDelegates: @NO,
      kTSKPinnedDomains :
          @{
              @"www.test.com" : @{
                      kTSKEnforcePinning : @YES,
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                              @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Fake key 2
                                              ]}}};
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Setup mocking of the reporter
    TSKBackgroundReporter *defaultReporter = [TrustKit getGlobalPinFailureReporter];
    id pinFailureReporterMock = [OCMockObject mockForClass:[TSKBackgroundReporter class]];
    [TrustKit setGlobalPinFailureReporter: pinFailureReporterMock];
    
    // Expect a report to be sent out when a notification is posted
    NSSet *knownPins = [NSSet setWithArray:@[[[NSData alloc]initWithBase64EncodedString:@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                                                                                options:(NSDataBase64DecodingOptions)0],
                                             [[NSData alloc]initWithBase64EncodedString:@"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                                                                                options:(NSDataBase64DecodingOptions)0]]];
    [[pinFailureReporterMock expect] pinValidationFailedForHostname:@"www.test.com"
                                                               port:nil
                                                   certificateChain:_testCertificateChain
                                                      notedHostname:@"www.test.com"
                                                         reportURIs:@[[NSURL URLWithString:@"https://overmind.datatheorem.com/trustkit/report"]]
                                                  includeSubdomains:NO
                                                  enforcePinning:YES
                                                          knownPins:knownPins
                                                   validationResult:TSKPinValidationResultErrorCouldNotGenerateSpkiHash];
    
    // Create a notification
    [[NSNotificationCenter defaultCenter] postNotificationName:kTSKValidationCompletedNotification
                                                        object:nil
                                                      userInfo:@{kTSKValidationDurationNotificationKey: @(1),
                                                                 kTSKValidationDecisionNotificationKey: @(1),
                                                                 kTSKValidationResultNotificationKey: @(TSKPinValidationResultErrorCouldNotGenerateSpkiHash),
                                                                 kTSKValidationCertificateChainNotificationKey: _testCertificateChain,
                                                                 kTSKValidationNotedHostnameNotificationKey: @"www.test.com",
                                                                 kTSKValidationServerHostnameNotificationKey: @"www.test.com"}];
    // Ensure that the reporter was called
    [pinFailureReporterMock verify];
    
    
    // Send a notification for a successful validation and ensure no report gets sent
    id pinSuccessReporterMock = [OCMockObject mockForClass:[TSKBackgroundReporter class]];
    [TrustKit setGlobalPinFailureReporter: pinSuccessReporterMock];
    [[NSNotificationCenter defaultCenter] postNotificationName:kTSKValidationCompletedNotification
                                                        object:nil
                                                      userInfo:@{kTSKValidationResultNotificationKey: @(TSKPinValidationResultSuccess)}];
    // Ensure that the reporter was NOT called
    [pinSuccessReporterMock verify];
    
#if !TARGET_OS_IPHONE
    // OS X - Send a notification for a failed validation due to a custom CA and ensure no report gets sent
    [[NSNotificationCenter defaultCenter] postNotificationName:kTSKValidationCompletedNotification
                                                        object:nil
                                                      userInfo:@{kTSKValidationResultNotificationKey: @(TSKPinValidationResultFailedUserDefinedTrustAnchor)}];
    // Ensure that the reporter was NOT called
    [pinSuccessReporterMock verify];
#endif
    
    // Cleanup
    [TrustKit setGlobalPinFailureReporter: defaultReporter];
    [TrustKit resetConfiguration];
}


- (void)testReporter
{
    // Just try a simple valid case to see if we can post this to the default report URL
    TSKBackgroundReporter *reporter = [[TSKBackgroundReporter alloc] initAndRateLimitReports:NO];
    [reporter pinValidationFailedForHostname:@"mail.example.com"
                                        port:[NSNumber numberWithInt:443]
                                       certificateChain:_testCertificateChain
                               notedHostname:@"example.com"
                                  reportURIs:@[[NSURL URLWithString:[TrustKit getDefaultReportUri]]]
                           includeSubdomains:YES
                           enforcePinning:YES
                                   knownPins:[NSSet setWithArray:@[
                                               [[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="
                                                                                  options:(NSDataBase64DecodingOptions)0],
                                               [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
                                                                                  options:(NSDataBase64DecodingOptions)0]]]
                            validationResult:TSKPinValidationResultFailed];
    
    [NSThread sleepForTimeInterval:2.0];
}


- (void)testReportsRateLimiter
{
    // Create the pin validation failure report
    NSArray *certificateChain = convertTrustToPemArray(_testTrust);
    NSArray *formattedPins = convertPinsToHpkpPins([NSSet setWithArray:@[[[NSData alloc]initWithBase64EncodedString:@"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM="
                                                                                                            options:(NSDataBase64DecodingOptions)0],
                                                                         [[NSData alloc]initWithBase64EncodedString:@"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g="
                                                                                                            options:(NSDataBase64DecodingOptions)0]]
                                                    ]);
    

    TSKPinFailureReport *report = [[TSKPinFailureReport alloc] initWithAppBundleId:@"test"
                                                                        appVersion:@"1.2.3"
                                                                       appPlatform:@"IOS"
                                                                       appVendorId:@"test"
                                                                   trustkitVersion:@"4.3.2.1"
                                                                          hostname:@"mail.example.com"
                                                                              port:[NSNumber numberWithInt:443]
                                                                          dateTime:[NSDate date]
                                                                     notedHostname:@"example.com"
                                                                 includeSubdomains:NO
                                                                 enforcePinning:NO
                                                         validatedCertificateChain:certificateChain
                                                                         knownPins:formattedPins
                                                                  validationResult:TSKPinValidationResultFailedCertificateChainNotTrusted];
    
    // Ensure the same report will not be sent twice in a row
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == NO, @"Wrongly rate-limited a new report");
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == YES, @"Did not rate-limit an identical report");
    
    // Set the last time the cache was reset to more than 24 hours ago and ensure the report is sent again
    [TSKReportsRateLimiter setLastReportsCacheResetDate:[[NSDate date] dateByAddingTimeInterval:-3700*24]];
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == NO, @"Reports cache was not properly reset after 24 hours");

    
    // Ensure the same report with a different validation result will be sent
    report = [[TSKPinFailureReport alloc] initWithAppBundleId:@"test"
                                                   appVersion:@"1.2.3"
                                                  appPlatform:@"IOS"
                                                  appVendorId:@"test"
                                              trustkitVersion:@"4.3.2.1"
                                                     hostname:@"mail.example.com"
                                                         port:[NSNumber numberWithInt:443]
                                                     dateTime:[NSDate date]
                                                notedHostname:@"example.com"
                                            includeSubdomains:NO
                                            enforcePinning:NO
                                    validatedCertificateChain:certificateChain
                                                    knownPins:formattedPins
                                             validationResult:TSKPinValidationResultFailed];
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == NO, @"Wrongly rate-limited a new report");
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == YES, @"Did not rate-limit an identical report");
    
    
    // Ensure the same report with a different hostname will be sent
    report = [[TSKPinFailureReport alloc] initWithAppBundleId:@"test"
                                                   appVersion:@"1.2.3"
                                                  appPlatform:@"IOS"
                                                  appVendorId:@"test"
                                              trustkitVersion:@"4.3.2.1"
                                                     hostname:@"other.example.com"
                                                         port:[NSNumber numberWithInt:443]
                                                     dateTime:[NSDate date]
                                                notedHostname:@"example.com"
                                            includeSubdomains:NO
                                               enforcePinning:NO
                                    validatedCertificateChain:certificateChain
                                                    knownPins:formattedPins
                                             validationResult:TSKPinValidationResultFailedCertificateChainNotTrusted];
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == NO, @"Wrongly rate-limited a new report");
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == YES, @"Did not rate-limit an identical report");
    
    
    // Ensure the same report with a different certificate chain will be sent
    report = [[TSKPinFailureReport alloc] initWithAppBundleId:@"test"
                                                   appVersion:@"1.2.3"
                                                  appPlatform:@"IOS"
                                                  appVendorId:@"test"
                                              trustkitVersion:@"4.3.2.1"
                                                     hostname:@"mail.example.com"
                                                         port:[NSNumber numberWithInt:443]
                                                     dateTime:[NSDate date]
                                                notedHostname:@"example.com"
                                            includeSubdomains:NO
                                            enforcePinning:NO
                                    validatedCertificateChain:[certificateChain subarrayWithRange:NSMakeRange(1, 2)]
                                                    knownPins:formattedPins
                                             validationResult:TSKPinValidationResultFailedCertificateChainNotTrusted];
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == NO, @"Wrongly rate-limited a new report");
    XCTAssert([TSKReportsRateLimiter shouldRateLimitReport:report] == YES, @"Did not rate-limit an identical report");
}



#if !TARGET_OS_IPHONE
- (void)testOSXIdentifierForVendor
{
    NSString *idfv = osx_identifier_for_vendor(@"com.fake.bundle.id");
    XCTAssertNotNil(idfv);
}
#endif

@end
