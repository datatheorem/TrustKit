/*
 
 TSKPublicKeyAlgorithmTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

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
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{kTSKPinnedDomains :
                                                  @{@"www.datatheorem.com" : @{
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                            kTSKPublicKeyHashes : @[@"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=", // Leaf Key
                                                                                    @"0SDf3cRToyZJaMsoS17oF72VMavLxj/N7WBNasNuiR8=", // Leaf Key
                                                                                    ]}}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.datatheorem.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.datatheorem.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.datatheorem.com"][kTSKPublicKeyHashes]);
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
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{kTSKPinnedDomains :
                                                  @{@"www.good.com" : @{
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                            kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server Key
                                                                                    @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server Key
                                                                                    ]}}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
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
    SecCertificateRef intermediateCertificate2 = [TSKCertificateUtils createCertificateFromDer:@"COMODOECCCertificationAuthority"];
    SecCertificateRef certChainArray[3] = {leafCertificate, intermediateCertificate, intermediateCertificate2};
    
    // If we put the real root CA, the test fails on OS X; using the last intermediate cert instead
    //SecCertificateRef rootCertificate = [TSKCertificateUtils createCertificateFromDer:@"AddTrustExternalRootCA"];
    SecCertificateRef trustStoreArray[1] = {intermediateCertificate2};
    
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:(const void **)trustStoreArray
                                                             arrayLength:sizeof(trustStoreArray)/sizeof(trustStoreArray[0])];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{kTSKPinnedDomains :
                                                  @{@"istlsfastyet.com" : @{
                                                            kTSKPublicKeyAlgorithms : @[kTSKAlgorithmEcDsaSecp256r1],
                                                            kTSKPublicKeyHashes : @[@"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=", // Server Key
                                                                                    @"rFjc3wG7lTZe43zeYTvPq8k4xdDEutCmIhI5dn4oCeE=", // Server Key
                                                                                    ]}}});
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"istlsfastyet.com",
                                            trustKitConfig[kTSKPinnedDomains][@"istlsfastyet.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"istlsfastyet.com"][kTSKPublicKeyHashes]);
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for ECDSA secp256r1");
}


@end
