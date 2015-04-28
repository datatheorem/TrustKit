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
#import "ssl_pin_verifier.h"
#import "public_key_utils.h"

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
    
    CFStringRef hostname = CFSTR("www.good.com");
    _policy = SecPolicyCreateSSL(true, hostname);

}

- (void)tearDown {
    
    CFRelease(_rootCertificate);
    CFRelease(_chainCertificate);
    CFRelease(_leafCertificate);
    CFRelease(_policy);
    
    [super tearDown];
}


// Pin to any of CA, Intermediate CA and Leaf certificates public keys (all valid) and ensure it succeeds
- (void)testWwwGoodComCertificateAgainstAnyPublicKey
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                                            @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);

    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the Intermediate CA certificate public key and ensure it succeeds
- (void)testWwwGoodComCertificateAgainstGoodIntermediateCAPublicKey
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=" // Intermediate key only
                                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];

    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the CA certificate public key and ensure it succeeds
- (void)testWwwGoodComCertificateAgainstGoodCAPublicKey
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);

    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the leaf certificate public key and ensure it succeeds
- (void)testWwwGoodComCertificateAgainstGoodLeafPublicKey
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=" // Server key only
                                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);

    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}

// Pin a bad key for www.good.com and ensure it fails

- (void)testWwwGoodComCertificateAgainstBadKeyPinning
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);

    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must NOT pass against invalid public key pins");
}


// Validation to domain names with no pins must never fail
- (void)testWwwGoodComCertificateWithNoPins
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", nil);

    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultDomainNotPinned, @"Validation must pass if no public key pins are set.");
}


// Pin a valid key for www.good.com and ensure it succeeds both with a trusted CA and a Self-Signed cert.
- (void)testWwwGoodComCertificateAgainstCAWithSelfSignedCAAsWell
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[//@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                            //@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                            @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0="//, // CA key
                                                                            //@"naw8JswG9YvBkitP4iGuyEgbFxssEMM/v4m7MglIzEw=" // Self-signed Key
                                                                            ]}});

    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[2] = {_rootCertificate, _selfCertificate };
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin a valid key for good.com with includeSubdomains and ensure the validation for www.good.com succeeds
- (void)testSubdomainWithGoodComCertificateAgainstGoodLeafPublicKey
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=" // Server key
                                                                                            ]}});
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin a bad key for good.com with includeSubdomains and ensure the validation for www.good.com fails
- (void)testSubdomainWithGoodComCertificateAgainstBadKeyPinning
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                            ]}});
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must NOT pass against invalid public key pins");
}


// Pin a bad key for good.com with includeSubdomains and a good key for www.good.com and ensure the validation for www.good.com succeeds
// (ie. the more specific pin should take precedence over the general good.com pin)
- (void)testSubdomainWithGoodComCertificateAgainstGoodLeafPublicKeyAndBadKeyAsWell
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                            ]}});
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid existing public key pins, regardless of an invalid key being present");
}


// Pin a valid key for good.com with includeSubdomains set to NO, and ensure the validation for www.good.com fails
- (void)testSubdomainWithGoodComCertificateAgainstAnyPublicKeyNotIncludingSubdomains
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                                            @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultDomainNotPinned, @"Validation must NOT pass because includeSubdomain is not enabled so wwww.good.com is not actually pinned");
}


// Tricky case: pin a bad key for good.co.uk with includeSubdomains and ensure the validation for www.good.com succeeds.
// Basically we want to make sure that TrustKit doesn’t confused with weird top-level domains (like .co.uk).
- (void)testWwwGoodComCertificateAgainstDifferentTLDPublicKeyPinning
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.co.uk" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Fake key
                                                                                            ]}});
    
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    TSKPinValidationResult verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig);
    
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultDomainNotPinned, @"Validation must pass as www.good.com domain shouldn't be pinned, when config is for a different TLD (co.uk)");
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

@end
