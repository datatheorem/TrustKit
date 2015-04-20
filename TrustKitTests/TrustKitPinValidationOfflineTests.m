//
//  TrustKitPinValidationOfflineTests.m
//  TrustKit
//
//  Created by Eric on 30/03/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "TrustKit.h"
#import "TrustKit+Private.h"
#import "TrustKitTestCertificates.h"
#import "subjectPublicKeyHash.h"

#define HEXDUMP_COLS 16

@interface TrustKitPinValidationOnlineTests : XCTestCase
@end


@interface TrustKitPinValidationOfflineTests : XCTestCase
{
    
}
@end

@implementation TrustKitPinValidationOfflineTests {
    SecCertificateRef _rootCertificate;
    SecCertificateRef _chainCertificate;
    SecCertificateRef _chainPlusSelfCertificate;
    SecCertificateRef _selfCertificate;
    SecCertificateRef _leafCertificate;
    SecPolicyRef _policy;
}

- (void)setUp {
    [super setUp];
                    
    CFDataRef rootData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"ca.cert" ofType:@"der"]];
    _rootCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, rootData);
    CFRelease(rootData);

    CFDataRef chainData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"ca-chain.cert" ofType:@"der"]];
    _chainCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, chainData);
    CFRelease(chainData);
    
    CFDataRef chainPlusSelfData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"ca-chain-plus-self.cert" ofType:@"der"]];
    _chainPlusSelfCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, chainPlusSelfData);
    CFRelease(chainPlusSelfData);
    
    CFDataRef selfData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"self.cert" ofType:@"der"]];
    _selfCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, selfData);
    CFRelease(selfData);
    
    CFDataRef leafData = (__bridge_retained CFDataRef)[NSData dataWithContentsOfFile:[[NSBundle bundleForClass:[self class]] pathForResource:@"www.good.com.cert" ofType:@"der"]];
    _leafCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, leafData);
    CFRelease(leafData);
    
    _policy = SecPolicyCreateSSL(true, NULL);
}

- (void)tearDown {
    
    CFRelease(_rootCertificate);
    CFRelease(_chainCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_policy);
    
    [super tearDown];
}

- (void)testWwwGoodComCertificateAgainstAnyPublicKey
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                      @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                      @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass against valid public key pins");
}
- (void)testWwwGoodComCertificateAgainstGoodIntermediateCAPublicKey
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=" // Intermediate key only
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass against valid public key pins");
}
- (void)testWwwGoodComCertificateAgainstGoodCAPublicKey
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass against valid public key pins");
}
- (void)testWwwGoodComCertificateAgainstGoodLeafPublicKey
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=" // Server key only
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass against valid public key pins");
}

- (void)testWwwGoodComCertificateAgainstBadKeyPinning
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == NO, @"Validation must NOT pass against invalid public key pins");
}

- (void)testWwwGoodComCertificateWithNoPins
{
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", nil);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass if no public key pins are set.");
}


// I don't understand this one
- (void)testWwwGoodComCertificateAgainstCAWithSelfSignedCAAsWell
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : @NO,
              kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
              kTSKPublicKeyHashes : @[//@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                      //@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                      @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0="//, // CA key
                                      //@"naw8JswG9YvBkitP4iGuyEgbFxssEMM/v4m7MglIzEw=" // Self-signed Key
                                      ]}};
    NSDictionary *trustKitConfig = parseTrustKitArguments(trustKitArguments);
    
    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;
    
    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");
    
    SecCertificateRef caRootArray[2] = {_rootCertificate, _selfCertificate };
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 2, NULL);
    
    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");
    
    BOOL verificationPassed = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);
    
    XCTAssert(verificationPassed == YES, @"Validation must pass against valid public key pins");
}

@end
