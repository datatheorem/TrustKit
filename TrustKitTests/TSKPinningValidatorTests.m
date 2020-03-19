/*
 
 TSKPinningValidatorTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "../TrustKit/public/TrustKit.h"
#import "../TrustKit/public/TSKPinningValidator.h"
#import "../TrustKit/public/TSKTrustKitConfig.h"
#import "../TrustKit/parse_configuration.h"
#import "../TrustKit/public/TSKPinningValidatorResult.h"
#import "../TrustKit/TSKPinningValidator_Private.h"
#import "../TrustKit/Pinning/TSKSPKIHashCache.h"

#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "../TrustKit/Reporting/reporting_utils.h"


#import "TSKCertificateUtils.h"
#import <OCMock/OCMock.h>

@interface TestAuthSender : NSObject<NSURLAuthenticationChallengeSender>
@end
@implementation TestAuthSender
- (void)useCredential:(NSURLCredential *)credential forAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)continueWithoutCredentialForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
- (void)cancelAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {}
@end

@interface TSKSPKIHashCache (TestSupport)
- (void)resetSubjectPublicKeyInfoDiskCache;
- (NSMutableDictionary<NSNumber *, SPKICacheDictionnary *> *)getSubjectPublicKeyInfoHashesCache;
- (NSMutableDictionary<NSNumber *, SPKICacheDictionnary *> *)loadSPKICacheFromFileSystem;
@end

static BOOL AllowsAdditionalTrustAnchors = YES; // toggle in tests if needed
@interface TestPinningValidator: TSKPinningValidator
@end
@implementation TestPinningValidator
+ (BOOL)allowsAdditionalTrustAnchors
{
    return AllowsAdditionalTrustAnchors;
}
@end


@interface TSKPinningValidatorTests : XCTestCase
@end

@implementation TSKPinningValidatorTests
{
    SecCertificateRef _rootCertificate;
    SecCertificateRef _selfSignedCertificate;
    SecCertificateRef _leafCertificate;
    SecCertificateRef _globalsignRootCertificate;
    
    TSKSPKIHashCache *spkiCache;
}


- (void)setUp
{
    [super setUp];
    
    // Create our certificate objects
    _rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    _leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    _selfSignedCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com.selfsigned"];
    _globalsignRootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GlobalSignRootCA"];
    
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = [[TSKSPKIHashCache alloc] initWithIdentifier:@"test"];
}


- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_selfSignedCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_globalsignRootCertificate);
    
    _rootCertificate = nil;
    _leafCertificate = nil;
    _selfSignedCertificate = nil;
    _globalsignRootCertificate = nil;
    
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
    spkiCache = nil;
    [super tearDown];
}


#pragma mark Tests for evaluateTrust:forHostname:

// Pin to any of CA, Intermediate CA and Leaf certificates public keys (all valid) and ensure it succeeds
- (void)testVerifyAgainstAnyPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw=", // Leaf key
                                                                           @"S5z3Fz5ZfZAGJOBZjK6TYBquyLLKO+BndKXBlL3nPjo=" // CA key
                                                                           ]}}};
    
    // Ensure the SPKI cache was on the filesystem is empty
    NSDictionary *fsCache = [spkiCache loadSPKICacheFromFileSystem];
    XCTAssert([fsCache[@1] count] == 0, @"SPKI cache for RSA 4096 must be empty before the test");
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    NSDictionary *domainConfig = parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"];
    
    TSKTrustEvaluationResult verificationResult = verifyPublicKeyPin(trust,
                                                                     @"www.good.com",
                                                                     domainConfig[kTSKPublicKeyHashes],
                                                                     spkiCache);
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationSuccess,
                   @"Validation must pass against valid public key pins");
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                  validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [validator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssertEqual(result, TSKTrustDecisionShouldAllowConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    // Ensure the SPKI cache was persisted to the filesystem
    fsCache = [spkiCache loadSPKICacheFromFileSystem];
    XCTAssertEqual([fsCache count], 1UL, @"SPKI cache for RSA 4096 must be persisted to the file system");
    
    CFRelease(trust);
}


// Pin only to the CA certificate public key and ensure it succeeds
- (void)testVerifyAgainstCAPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"S5z3Fz5ZfZAGJOBZjK6TYBquyLLKO+BndKXBlL3nPjo=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationFailedNoMatchingPin;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationSuccess,
                   @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"],
                   TSKTrustDecisionShouldAllowConnection);
    
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin only to the leaf certificate public key and ensure it succeeds
- (void)testVerifyAgainstLeafPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw=", // Leaf Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationFailedNoMatchingPin;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationSuccess,
                   @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"],
                   TSKTrustDecisionShouldAllowConnection);
    
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin a bad key and ensure validation fails
- (void)testVerifyAgainstBadPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Bad key 2
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationFailedNoMatchingPin,
                   @"Validation must fail against bad public key pins");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedNoMatchingPin);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [validator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssertEqual(result, TSKTrustDecisionShouldBlockConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin a bad key but the pinning policy expired and ensure the connection is left untouched
- (void)testVerifyAgainstBadPublicKeyPinsExpired
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   // Totally expired
                                                   kTSKExpirationDate: @"2015-01-01",
                                                   kTSKEnforcePinning: @YES,
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Bad key 2
                                                                           ]}}};
    
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    // Test TSKPinningValidator
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTFail(@"Should not be invoked");
                                                }];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [validator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssertEqual(result, TSKTrustDecisionDomainNotPinned);
    
    CFRelease(trust);
}

// Pin a bad key but do not enforce pinning and ensure the connection is allowed
- (void)testVerifyAgainstBadPublicKeyPinningNotEnforced
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKEnforcePinning: @NO,
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Bad key 2
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationFailedNoMatchingPin, @"Validation must fail against bad public key pins");
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedNoMatchingPin);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [validator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssertEqual(result, TSKTrustDecisionShouldAllowConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin a bad key and a good key and ensure validation succeeds
- (void)testVerifyAgainstLeafPublicKeyAndBadPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad key
                                                                           @"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw="  // Leaf key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationSuccess,
                   @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldAllowConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationSuccess);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"],
                   TSKTrustDecisionShouldAllowConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin the valid CA key with an invalid certificate chain and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadCertificateChain
{
    // The leaf certificate is self-signed
    SecCertificateRef certChainArray[1] = {_selfSignedCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKEnforcePinning: @NO,  // Should fail even if pinning is not enforced
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationFailedInvalidCertificateChain,
                   @"Validation must fail against bad certificate chain");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedInvalidCertificateChain);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    // Call TSKPinningValidator
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"],
                   TSKTrustDecisionShouldBlockConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin the valid CA key with an valid certificate chain but a wrong hostname and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadHostname
{
    // The certificate chain is valid for www.good.com but we are connecting to www.bad.com
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.bad.com" : @{
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.bad.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.bad.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationFailedInvalidCertificateChain,
                   @"Validation must fail against bad hostname");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedInvalidCertificateChain);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.bad.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.bad.com"],
                   TSKTrustDecisionShouldBlockConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


// Pin the valid CA key but serve a different valid chain with the (unrelared) pinned CA certificate injected at the end
- (void)testVerifyAgainstInjectedCaPublicKey
{
    // The certificate chain is valid for www.good.com but does not contain the pinned CA certificate, which we inject as an additional certificate
    SecCertificateRef certChainArray[2] = {_leafCertificate, _globalsignRootCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"cGuxAXyFXFkWm61cF4HPWX8S0srS9j0aSqN0k4AP+4A=", // Globalsign CA
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKTrustEvaluationResult verificationResult = TSKTrustEvaluationErrorInvalidParameters;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    
    XCTAssertEqual(verificationResult, TSKTrustEvaluationFailedNoMatchingPin,
                   @"Validation must fail against injected pinned CA");
    
    
    // Then test TSKPinningValidator
    XCTestExpectation *expectation = [self expectationWithDescription:@"ValidationResultHandler"];
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTAssertEqual(result.finalTrustDecision, TSKTrustDecisionShouldBlockConnection);
                                                    
                                                    XCTAssertEqual(result.evaluationResult, TSKTrustEvaluationFailedNoMatchingPin);
                                                    
                                                    XCTAssertEqualObjects(result.certificateChain, convertTrustToPemArray(trust));
                                                    
                                                    XCTAssertEqualObjects(notedHostname, @"www.good.com");
                                                    
                                                    [expectation fulfill];
                                                }];
    
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.good.com"],
                   TSKTrustDecisionShouldBlockConnection);
    
    // Ensure a validation notification was posted
    [self waitForExpectationsWithTimeout:2.0 handler:nil];
    
    CFRelease(trust);
}


- (void)testDomainNotPinned
{
    // The certificate chain is valid for www.good.com but we are connecting to www.nonpinned.com
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    // Then test TSKPinningValidator
    TSKPinningValidator *validator;
    validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                              hashCache:spkiCache
                                          ignorePinsForUserTrustAnchors:NO
                                                validationCallbackQueue:dispatch_get_main_queue()
                                                     validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                    XCTFail(@"Should not invoke callback");
                                                }];
    
    // Call TSKPinningValidator
    XCTAssertEqual([validator evaluateTrust:trust forHostname:@"www.nonpinned.com"],
                   TSKTrustDecisionDomainNotPinned);
    
    CFRelease(trust);
}


#pragma mark Tests for handleChallenge:completionHandler:

// Ensure handleChallenge:completionHandler: properly calls evaluateTrust:forHostname:
-(void) testHandleChallengeCompletionHandlerDomainNotPinned
{
    // The certificate chain is valid for www.good.com but we are connecting to www.nonpinned.com
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    TrustKit *tk = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // For a non-pinned domain, we expect the default SSL validation to be called
        XCTAssertEqual(disposition, NSURLSessionAuthChallengePerformDefaultHandling);
        XCTAssertNil(credential);
        wasHandlerCalled = YES;
    };
    
    // Mock a protection space
    id protectionSpaceMock = [OCMockObject mockForClass:[NSURLProtectionSpace class]];
    OCMStub([protectionSpaceMock authenticationMethod]).andReturn(NSURLAuthenticationMethodServerTrust);
    OCMStub([protectionSpaceMock host]).andReturn(@"www.nonpinned.com");
    OCMStub([protectionSpaceMock serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    id challengeMock = [OCMockObject mockForClass:[NSURLAuthenticationChallenge class]];
    OCMStub([challengeMock protectionSpace]).andReturn(protectionSpaceMock);
    
    // Test the helper method
    BOOL wasChallengeHandled = [tk.pinningValidator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssertTrue(wasChallengeHandled);
    XCTAssertTrue(wasHandlerCalled);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerPinningFailed
{
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKEnforcePinning: @YES,
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", //Fake Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinningValidator *validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                                                   hashCache:spkiCache
                                                               ignorePinsForUserTrustAnchors:YES
                                                                     validationCallbackQueue:dispatch_get_main_queue()
                                                                          validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                                         //
                                                                     }];
    
    // Mock a protection space
    id protectionSpaceMock = [OCMockObject mockForClass:[NSURLProtectionSpace class]];
    OCMStub([protectionSpaceMock authenticationMethod]).andReturn(NSURLAuthenticationMethodServerTrust);
    OCMStub([protectionSpaceMock host]).andReturn(@"www.good.com");
    OCMStub([protectionSpaceMock serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    id challengeMock = [OCMockObject mockForClass:[NSURLAuthenticationChallenge class]];
    OCMStub([challengeMock protectionSpace]).andReturn(protectionSpaceMock);
    
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // For a pinning failure, we expect the authentication challenge to be cancelled
        XCTAssertEqual(disposition, NSURLSessionAuthChallengeCancelAuthenticationChallenge);
        XCTAssertNil(credential);
        wasHandlerCalled = YES;
    };
    
    // Test the helper method
    BOOL wasChallengeHandled = [validator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssertTrue(wasChallengeHandled);
    XCTAssertTrue(wasHandlerCalled);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerPinningSuccessful
{
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"TwyNzy19zZi7cKfPsucs1E+h8ODOCPMrT8681sFWJvw=", // CA Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    
    
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinningValidator *validator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:parsedTrustKitConfig[kTSKPinnedDomains]
                                                                                   hashCache:spkiCache
                                                               ignorePinsForUserTrustAnchors:YES
                                                                     validationCallbackQueue:dispatch_get_main_queue()
                                                                          validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, NSDictionary<TSKDomainConfigurationKey, id> *_Nonnull notedHostnamePinningPolicy) {
                                                                         //
                                                                     }];
    
    // Mock a protection space
    NSURLProtectionSpace *protectionSpace = OCMPartialMock([[NSURLProtectionSpace alloc] initWithHost:@"www.good.com"
                                                                                                 port:443
                                                                                             protocol:NSURLProtectionSpaceHTTPS
                                                                                                realm:nil
                                                                                 authenticationMethod:NSURLAuthenticationMethodServerTrust]);
    
    NSURLCredential *credential = [NSURLCredential credentialForTrust:trust];
    OCMStub([protectionSpace serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    NSURLAuthenticationChallenge *challenge = [[NSURLAuthenticationChallenge alloc] initWithProtectionSpace:protectionSpace
                                                                                         proposedCredential:credential
                                                                                       previousFailureCount:0
                                                                                            failureResponse:nil
                                                                                                      error:nil
                                                                                                     sender:[TestAuthSender new]];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable gotCredential)
    {
        // For a pinning success, we expect the authentication challenge to use the supplied credential
        XCTAssertEqual(disposition, NSURLSessionAuthChallengeUseCredential);
        XCTAssertEqualObjects(gotCredential, credential);
        wasHandlerCalled = YES;
    };
    
    // Test the helper method
    BOOL wasChallengeHandled = [validator handleChallenge:challenge completionHandler:completionHandler];
    
    XCTAssertTrue(wasChallengeHandled);
    XCTAssertTrue(wasHandlerCalled);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerNotServerTrustAuthenticationMethod
{
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    TrustKit *tk = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // This should not be called when the challenge is not for server trust
        wasHandlerCalled = YES;
    };
    
    // Mock a protection space
    id protectionSpaceMock = [OCMockObject mockForClass:[NSURLProtectionSpace class]];
    // Not a server trust challenge
    OCMStub([protectionSpaceMock authenticationMethod]).andReturn(NSURLAuthenticationMethodNTLM);
    OCMStub([protectionSpaceMock host]).andReturn(@"www.good.com");
    OCMStub([protectionSpaceMock serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    id challengeMock = [OCMockObject mockForClass:[NSURLAuthenticationChallenge class]];
    OCMStub([challengeMock protectionSpace]).andReturn(protectionSpaceMock);
    
    // Test the helper method
    BOOL wasChallengeHandled = [tk.pinningValidator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssertFalse(wasChallengeHandled);
    XCTAssertFalse(wasHandlerCalled);
    
    CFRelease(trust);
}

- (void)testExcludedSubdomain
{
    // Create a valid server trust
    SecCertificateRef certChainArray[1] = {_leafCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKSwizzleNetworkDelegates: @NO,
                                     kTSKPinnedDomains : @{
                                             @"good.com" : @{
                                                     kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                             @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                             ],
                                                     kTSKIncludeSubdomains: @YES},
                                             @"unsecured.good.com": @{
                                                     kTSKExcludeSubdomainFromParentPolicy: @YES
                                                     }
                                             }};
    
    // Then test TSKPinningValidator
    TrustKit *tk = [[TrustKit alloc] initWithConfiguration:trustKitConfig];
    
    XCTAssertEqual([tk.pinningValidator evaluateTrust:trust forHostname:@"unsecured.good.com"],
                   TSKTrustDecisionDomainNotPinned);
    
    CFRelease(trust);
}

@end
