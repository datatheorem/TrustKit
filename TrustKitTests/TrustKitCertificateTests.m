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

    // These certificates were generated with a different ASN.1 header, since TrustKit includes
    // a different one by default, let's change it (this functionality is private)

    [TKSettings setDefaultRsaAsn1Header:[NSData dataWithBytes:rsa_asn1_header length:sizeof(rsa_asn1_header)]];

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
    [TKSettings setPublicKeyPins:@{
            @"www.good.com" : @[
                    @"4d012d74c6e6c058185227cce0b0c5fb1804b5dd33ebd98f1a6929d35e1de996", //Server key
                    @"921288e9a7b89a2704bd7ef8301fc1678bb5e560961973c3e868e0ea221155e1", //Intermediate key
                    @"890324e289eb249cff9f05b5c02511d1872c877a2685b33e3ea304c0da1ffcad" //CA key
            ]}];

    SecCertificateRef trustCertArray[2] = {_chainCertificate, _leafCertificate};
    CFArrayRef certs = CFArrayCreate(NULL, (const void **) trustCertArray, 2, NULL);
    SecTrustRef trust;

    XCTAssert(SecTrustCreateWithCertificates(certs, _policy, &trust) == errSecSuccess, @"SecTrustCreateWithCertificates did not return errSecSuccess");

    SecCertificateRef caRootArray[1] = {_rootCertificate};
    CFArrayRef caRootCertificates = CFArrayCreate(NULL, (const void **) caRootArray, 1, NULL);

    XCTAssert(SecTrustSetAnchorCertificates(trust, caRootCertificates) == errSecSuccess, @"SecTrustSetAnchorCertificates did not return errSecSuccess");

    BOOL verificationPassed = verifyCertificatePin(trust, @"www.good.com");

    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);

    XCTAssert(verificationPassed == YES, @"Validation must past against valid public key pins");
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

    BOOL verificationPassed = verifyCertificatePin(trust, @"www.good.com");

    CFRelease(caRootCertificates);
    CFRelease(certs);
    CFRelease(trust);

    XCTAssert(verificationPassed == NO, @"Validation must NOT pass if no public key pins are set.");
}


@end
