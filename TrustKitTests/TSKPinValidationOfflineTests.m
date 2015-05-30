//
//  TSKPinValidationOfflineTests.m
//  TrustKit
//
//  Created by Eric on 30/03/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "ssl_pin_verifier.h"
#import "public_key_utils.h"

#define HEXDUMP_COLS 16


@interface TSKPinValidationOfflineTests : XCTestCase
{
    
}
@end

@implementation TSKPinValidationOfflineTests {
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
    
    // Enable hostname validation in the SSL policy
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
- (void)testVerifyAgainstAnyPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                                            @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});

    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the Intermediate CA certificate public key and ensure it succeeds
- (void)testVerifyAgainstIntermediateCAPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];

    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=" // Intermediate key only
                                                                                            ]}});

    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the CA certificate public key and ensure it succeeds
- (void)testVerifyAgainstCAPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];

    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key only
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin only to the leaf certificate public key and ensure it succeeds
- (void)testVerifyAgainstLeafPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=" // Leaf key only
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
}


// Pin a bad key and ensure validation fails
- (void)testVerifyAgainstBadPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Bad key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must NOT pass against invalid public key pins");
}


// Pin a bad key and a good key and ensure validation succeeds
- (void)testVerifyAgainstLeafPublicKeyAndBadPublicKey
{
    SecCertificateRef trustCertArray[2] = {_leafCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad key
                                                                                            @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="  // Leaf key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against a good and an invalid public key pins");
}

// Pin the valid CA key with an invalid certificate chain and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadCertificateChain
{
    // The leaf certificate is self-signed
    SecCertificateRef trustCertArray[2] = {_selfCertificate, _chainCertificate};
    SecCertificateRef caRootArray[1] = {_rootCertificate};
    
    SecTrustRef trust = [self _createTrustWithCertificates:(const void **)trustCertArray arrayLength:sizeof(trustCertArray)/sizeof(trustCertArray[0])
                                        anchorCertificates:(const void **)caRootArray arrayLength:sizeof(caRootArray)/sizeof(caRootArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailedInvalidCertificateChain, @"Validation must fail against an invalid certificate chain");
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
