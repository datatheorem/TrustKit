/*
 
 TSKPinningValidatorTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "ssl_pin_verifier.h"
#import "public_key_utils.h"
#import "parse_configuration.h"
#import "TSKCertificateUtils.h"
#import <OCMock/OCMock.h>


@interface TSKPinningValidatorTests : XCTestCase
{
    
}
@end

@implementation TSKPinningValidatorTests
{
    SecCertificateRef _rootCertificate;
    SecCertificateRef _intermediateCertificate;
    SecCertificateRef _selfSignedCertificate;
    SecCertificateRef _leafCertificate;
    SecCertificateRef _comodoRootCertificate;
}


- (void)setUp
{
    [super setUp];
    // Create our certificate objects
    _rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    _intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodIntermediateCA"];
    _leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    _selfSignedCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com.selfsigned"];
    _comodoRootCertificate = [TSKCertificateUtils createCertificateFromDer:@"COMODORSACertificationAuthority"];
    
    [TrustKit resetConfiguration];
}


- (void)tearDown
{
    [TrustKit resetConfiguration];
    CFRelease(_rootCertificate);
    CFRelease(_intermediateCertificate);
    CFRelease(_leafCertificate);
    [super tearDown];
}


#pragma mark Tests for evaluateTrust:forHostname:

// Pin to any of CA, Intermediate CA and Leaf certificates public keys (all valid) and ensure it succeeds
- (void)testVerifyAgainstAnyPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                           @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                           @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                           ]}}};
    
    // Ensure the SPKI cache was on the filesystem is empty
    XCTAssert([getSpkiCacheFromFileSystem()[@1] count] == 0, @"SPKI cache for RSA 4096 must be empty before the test");
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];

    // Call TSKPinningValidator
    TSKTrustDecision result = [TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssert(result == TSKTrustDecisionShouldAllowConnection);

    // Ensure the SPKI cache was persisted to the filesystem
    XCTAssert([getSpkiCacheFromFileSystem()[@1] count] == 1, @"SPKI cache for RSA 4096 must be persisted to the file system");
    
    CFRelease(trust);
}


// Pin only to the Intermediate CA certificate public key and ensure it succeeds
- (void)testVerifyAgainstIntermediateCAPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // Ensure the SPKI cache was on the filesystem is empty
    XCTAssert([getSpkiCacheFromFileSystem()[@1] count] == 0, @"SPKI cache for RSA 4096 must be empty before the test");
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"] == TSKTrustDecisionShouldAllowConnection);
    
    
    // Ensure the SPKI cache was persisted to the filesystem
    XCTAssert([getSpkiCacheFromFileSystem()[@1] count] == 2, @"SPKI cache for RSA 4096 must be persisted to the file system");
    
    CFRelease(trust);
}


// Pin only to the CA certificate public key and ensure it succeeds
- (void)testVerifyAgainstCAPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"] == TSKTrustDecisionShouldAllowConnection);
    CFRelease(trust);
}


// Pin only to the leaf certificate public key and ensure it succeeds
- (void)testVerifyAgainstLeafPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Leaf Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"] == TSKTrustDecisionShouldAllowConnection);
    CFRelease(trust);
}


// Pin a bad key and ensure validation fails
- (void)testVerifyAgainstBadPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Bad key 2
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must fail against bad public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssert(result == TSKTrustDecisionShouldBlockConnection);
    
    CFRelease(trust);
}


// Pin a bad key but do not enforce pinning and ensure the connection is allowed
- (void)testVerifyAgainstBadPublicKeyPinningNotEnforced
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKEnforcePinning: @NO,
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" // Bad key 2
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must fail against bad public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssert(result == TSKTrustDecisionShouldAllowConnection);
    
    CFRelease(trust);
}



// Pin a bad key and a good key and ensure validation succeeds
- (void)testVerifyAgainstLeafPublicKeyAndBadPublicKey
{
    // Create a valid server trust
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad key
                                                                           @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="  // Leaf key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"] == TSKTrustDecisionShouldAllowConnection);
    CFRelease(trust);
}


// Pin the valid CA key with an invalid certificate chain and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadCertificateChain
{
    // The leaf certificate is self-signed
    SecCertificateRef certChainArray[2] = {_selfSignedCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKEnforcePinning: @NO,  // Should fail even if pinning is not enforced
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultFailedCertificateChainNotTrusted, @"Validation must fail against bad certificate chain");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"];
    XCTAssert(result == TSKTrustDecisionShouldBlockConnection);
    
    CFRelease(trust);
}


// Pin the valid CA key with an valid certificate chain but a wrong hostname and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadHostname
{
    // The certificate chain is valid for www.good.com but we are connecting to www.bad.com
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.bad.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.bad.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.bad.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.bad.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKPinValidationResultFailedCertificateChainNotTrusted, @"Validation must fail against bad hostname");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.bad.com"] == TSKTrustDecisionShouldBlockConnection);
    CFRelease(trust);
}


// Pin the valid CA key but serve a different valid chain with the (unrelared) pinned CA certificate injected at the end
- (void)testVerifyAgainstInjectedCaPublicKey
{
    // The certificate chain is valid for www.good.com but does not contain the pinned CA certificate, which we inject as an additional certificate
    SecCertificateRef certChainArray[3] = {_leafCertificate, _comodoRootCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                   kTSKPublicKeyHashes : @[@"grX4Ta9HpZx6tSHkmCrvpApTQGo67CYDnvprLg5yRME=", // Comodo CA
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    // First test the verifyPublicKeyPin() function
    NSDictionary *parsedTrustKitConfig = parseTrustKitConfiguration(trustKitConfig);
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            parsedTrustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    
    XCTAssert(verificationResult == TSKTrustDecisionShouldBlockConnection, @"Validation must fail against injected pinned CA");
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    XCTAssert([TSKPinningValidator evaluateTrust:trust forHostname:@"www.good.com"] == TSKTrustDecisionShouldBlockConnection);
    CFRelease(trust);
}


- (void)testDomainNotPinned
{
    // The certificate chain is valid for www.good.com but we are connecting to www.nonpinned.com
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    
    
    // Then test TSKPinningValidator
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    // Call TSKPinningValidator
    TSKTrustDecision result = [TSKPinningValidator evaluateTrust:trust forHostname:@"www.nonpinned.com"];
    XCTAssert(result == TSKTrustDecisionDomainNotPinned);
    
    CFRelease(trust);
}


#pragma mark Tests for handleChallenge:completionHandler:

// Ensure handleChallenge:completionHandler: properly calls evaluateTrust:forHostname:
-(void) testHandleChallengeCompletionHandlerDomainNotPinned
{
    // The certificate chain is valid for www.good.com but we are connecting to www.nonpinned.com
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                           ]}}};
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // For a non-pinned domain, we expect the default SSL validation to be called
        XCTAssert(disposition == NSURLSessionAuthChallengePerformDefaultHandling);
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
    BOOL wasChallengeHandled = [TSKPinningValidator handleChallenge:challengeMock completionHandler:completionHandler];

    XCTAssert(wasChallengeHandled == YES);
    XCTAssert(wasHandlerCalled == YES);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerPinningFailed
{
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", //Fake Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // For a pinning failure, we expect the authentication challenge to be cancelled
        XCTAssert(disposition == NSURLSessionAuthChallengeCancelAuthenticationChallenge);
        XCTAssertNil(credential);
        wasHandlerCalled = YES;
    };
    
    // Mock a protection space
    id protectionSpaceMock = [OCMockObject mockForClass:[NSURLProtectionSpace class]];
    OCMStub([protectionSpaceMock authenticationMethod]).andReturn(NSURLAuthenticationMethodServerTrust);
    OCMStub([protectionSpaceMock host]).andReturn(@"www.good.com");
    OCMStub([protectionSpaceMock serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    id challengeMock = [OCMockObject mockForClass:[NSURLAuthenticationChallenge class]];
    OCMStub([challengeMock protectionSpace]).andReturn(protectionSpaceMock);
    
    // Test the helper method
    BOOL wasChallengeHandled = [TSKPinningValidator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssert(wasChallengeHandled == YES);
    XCTAssert(wasHandlerCalled == YES);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerPinningSuccessful
{
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    __block BOOL wasHandlerCalled = NO;
    void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable) = ^void(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential * _Nullable credential)
    {
        // For a pinning success, we expect the authentication challenge to use the supplied credential
        XCTAssert(disposition == NSURLSessionAuthChallengeUseCredential);
        XCTAssertTrue([credential isEqual:[NSURLCredential credentialForTrust:trust]]);
        wasHandlerCalled = YES;
    };
    
    // Mock a protection space
    id protectionSpaceMock = [OCMockObject mockForClass:[NSURLProtectionSpace class]];
    OCMStub([protectionSpaceMock authenticationMethod]).andReturn(NSURLAuthenticationMethodServerTrust);
    OCMStub([protectionSpaceMock host]).andReturn(@"www.good.com");
    OCMStub([protectionSpaceMock serverTrust]).andReturn(trust);
    
    // Mock an authentication challenge
    id challengeMock = [OCMockObject mockForClass:[NSURLAuthenticationChallenge class]];
    OCMStub([challengeMock protectionSpace]).andReturn(protectionSpaceMock);
    
    // Test the helper method
    BOOL wasChallengeHandled = [TSKPinningValidator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssert(wasChallengeHandled == YES);
    XCTAssert(wasHandlerCalled == YES);
    
    CFRelease(trust);
}


-(void) testHandleChallengeCompletionHandlerNotServerTrustAuthenticationMethod
{
    SecCertificateRef certChainArray[2] = {_leafCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    
    // Create a configuration
    NSDictionary *trustKitConfig = @{kTSKPinnedDomains :
                                         @{@"www.good.com" : @{
                                                   kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                   kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=", // CA Key
                                                                           @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", // Fake key
                                                                           ]}}};
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
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
    BOOL wasChallengeHandled = [TSKPinningValidator handleChallenge:challengeMock completionHandler:completionHandler];
    
    XCTAssert(wasChallengeHandled == NO);
    XCTAssert(wasHandlerCalled == NO);
    
    CFRelease(trust);
}


@end
