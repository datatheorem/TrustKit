//
//  TrustKitCertificateTests.m
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

@interface TrustKitServerTests : XCTestCase
@end


@interface TrustKitCertificateTests : XCTestCase
{
    
}
@end

@implementation TrustKitCertificateTests {
    SecCertificateRef _rootCertificate;
    SecCertificateRef _chainCertificate;
    SecCertificateRef _leafCertificate;
    SecPolicyRef _policy;
}

- (void)setUp {
    [super setUp];
    
    CFDataRef rootData = CFDataCreate(kCFAllocatorDefault, ca_cert_der, (CFIndex)ca_cert_der_len);
    _rootCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, rootData);
    CFRelease(rootData);
    
    CFDataRef chainData = CFDataCreate(kCFAllocatorDefault, ca_chain_cert_der, (CFIndex)ca_chain_cert_der_len);
    _chainCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, chainData);
    CFRelease(chainData);
    
    CFDataRef leafData = CFDataCreate(kCFAllocatorDefault, www_good_com_cert_der, (CFIndex)www_good_com_cert_der_len);
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

- (void)testWwwGoodComCertificateAgainstGoodIntermediateCA
{
    NSDictionary *trustKitArguments =
    @{
      @"www.good.com" : @{
              kTSKIncludeSubdomains : [NSNumber numberWithBool:NO],
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


@end
