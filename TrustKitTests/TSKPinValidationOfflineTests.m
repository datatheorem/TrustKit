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
#import "TSKCertificateUtils.h"


@interface TSKPinValidationOfflineTests : XCTestCase
{
    
}
@end

@implementation TSKPinValidationOfflineTests
{
    SecCertificateRef _rootCertificate;
    SecCertificateRef _intermediateCertificate;
    SecCertificateRef _selfSignedCertificate;
    SecCertificateRef _leafCertificate;
}


- (void)setUp
{
    [super setUp];
    // Create our certificate objects
    _rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    _intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodIntermediateCA"];
    _leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    _selfSignedCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com.selfsigned"];
}


- (void)tearDown
{
    CFRelease(_rootCertificate);
    CFRelease(_intermediateCertificate);
    CFRelease(_leafCertificate);
    [super tearDown];
}


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
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            @"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=", // Intermediate key
                                                                                            @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});

    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
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

    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"khKI6ae4micEvX74MB/BZ4u15WCWGXPD6Gjg6iIRVeE=" // Intermediate key only
                                                                                            ]}});

    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
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
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key only
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);

    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
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
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=" // Leaf key only
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins");
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
    
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Bad key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailed, @"Validation must NOT pass against invalid public key pins");
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
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Bad key
                                                                                            @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="  // Leaf key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against a good and an invalid public key pins");
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
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailedInvalidCertificateChain, @"Validation must fail against an invalid certificate chain");
}


// Pin the valid CA key with an valid certificate chain but a wrong hostname and ensure validation fails
- (void)testVerifyAgainstCaPublicKeyAndBadHostname
{
    // The certificate chain is valid for www.good.com but we are connecting to www.bad.com
    SecCertificateRef certChainArray[2] = {_selfSignedCertificate, _intermediateCertificate};
    SecCertificateRef trustStoreArray[1] = {_rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.bad.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=" // CA key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.bad.com", trustKitConfig[@"www.bad.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.bad.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    
    XCTAssert(verificationResult == TSKPinValidationResultFailedInvalidCertificateChain, @"Validation must fail against an invalid hostname");
}


@end
