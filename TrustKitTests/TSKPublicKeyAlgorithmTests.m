//
//  TSKPublicKeyAlgorithmTests.m
//  TrustKit
//
//  Created by Alban Diquet on 5/31/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "ssl_pin_verifier.h"
#import "public_key_utils.h"
#import "TSKCertificateUtils.h"


@interface TSKPublicKeyAlgorithmTests : XCTestCase
{
    
}
@end

@implementation TSKPublicKeyAlgorithmTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


- (void)testVerifyRsa2048
{
    // Create a valid server trust
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.datatheorem.com"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"ThawteSSLCA"];
    SecCertificateRef certChainArray[2] = {leafCertificate, intermediateCertificate};
    
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:NULL
                                                             arrayLength:0];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.datatheorem.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                                    kTSKPublicKeyHashes : @[@"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=", // Leaf key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.datatheorem.com", trustKitConfig[@"www.datatheorem.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.datatheorem.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for RSA 2048");
}


- (void)testVerifyRsa4096
{
    // Create a valid server trust
    SecCertificateRef rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodRootCA"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GoodIntermediateCA"];
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    SecCertificateRef certChainArray[2] = {leafCertificate, intermediateCertificate};
    
    SecCertificateRef trustStoreArray[1] = {rootCertificate};
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"www.good.com", trustKitConfig[@"www.good.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"www.good.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    CFRelease(rootCertificate);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for RSA 4096");
}


- (void)testVerifyEcDsaSecp256r1
{
    // Create a valid server trust
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"sni41871.cloudflaressl.com"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"COMODOECCDomainValidationSecureServerCA2"];
    SecCertificateRef certChainArray[2] = {leafCertificate, intermediateCertificate};
    
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:NULL
                                                             arrayLength:0];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"istlsfastyet.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmEcDsaSecp256r1],
                                                                    kTSKPublicKeyHashes : @[@"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=", // Server key
                                                                                            ]}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust, @"istlsfastyet.com", trustKitConfig[@"istlsfastyet.com"][kTSKPublicKeyAlgorithms], trustKitConfig[@"istlsfastyet.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for ECDSA secp256r1");
}


@end
