/*
 
 TSKPublicKeyAlgorithmTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "../TrustKit/TrustKit+Private.h"
#import "../TrustKit/parse_configuration.h"

#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/Pinning/public_key_utils.h"
#import "../TrustKit/Reporting/reporting_utils.h"

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
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GlobalSignDomainValidationCA-SHA256-G2"];
    //SecCertificateRef intermediateCertificate2 = [TSKCertificateUtils createCertificateFromDer:@"GlobalSignRootCA"];
    SecCertificateRef certChainArray[2] = {leafCertificate, intermediateCertificate};//, intermediateCertificate2};
    
    SecTrustRef trust = [TSKCertificateUtils createTrustWithCertificates:(const void **)certChainArray
                                                             arrayLength:sizeof(certChainArray)/sizeof(certChainArray[0])
                                                      anchorCertificates:NULL
                                                             arrayLength:0];
    
    // Create a configuration and parse it so we get the right format
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"www.globalsign.com" : @{
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                                kTSKPublicKeyHashes : @[@"iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0=", // CA Key
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                                        ]}}});
    
    // Initialize the SPKI cache manually and don't load an existing cache from the filesystem
    initializeSubjectPublicKeyInfoCache();
    XCTAssert([getSpkiCache()[@0] count] == 0, @"SPKI cache for RSA 2048 must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.globalsign.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.globalsign.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.globalsign.com"][kTSKPublicKeyHashes]);
    
    // Ensure the SPKI cache was used; the full certificate chain is four certs and we have to go through all of them to get to the pinned leaf
    XCTAssert([getSpkiCache()[@0] count] == 1, @"SPKI cache for RSA 2048 must have been used");

    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    resetSubjectPublicKeyInfoCache();
    
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
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"www.good.com" : @{
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server Key
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                                        ]}}});
    
    // Initialize the SPKI cache manually and don't load an existing cache from the filesystem
    initializeSubjectPublicKeyInfoCache();
    XCTAssert([getSpkiCache()[@1] count] == 0, @"SPKI cache for RSA 4096 must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    // Ensure the SPKI cache was used; the full certificate chain is three certs and we have to go through all of them to get to the pinned leaf
    XCTAssert([getSpkiCache()[@1] count] == 3, @"SPKI cache for RSA 4096 must have been used");
    
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    CFRelease(rootCertificate);
    resetSubjectPublicKeyInfoCache();
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for RSA 4096");
}


- (void)testVerifyEcDsaSecp256r1
{
    // Create a valid server trust
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"www.cloudflare.com"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"COMODOECCExtendedValidationSecureServerCA"];
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
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"www.cloudflare.com" : @{
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmEcDsaSecp256r1],
                                                                kTSKPublicKeyHashes : @[@"Gc7EN2acfkbE0dUOAd34tr1XLr+JdkTiTrMAfhESQHI=", // Leaf Key
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                                        ]}}});
    
    // Initialize the SPKI cache manually and don't load an existing cache from the filesystem
    initializeSubjectPublicKeyInfoCache();
    XCTAssert([getSpkiCache()[@2] count] == 0, @"SPKI cache for EC DSA must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.cloudflare.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.cloudflare.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.cloudflare.com"][kTSKPublicKeyHashes]);
    
    // Ensure the SPKI cache was used; the full certificate chain is three certs and we have to go through all of them to get to the pinned leaf
    XCTAssert([getSpkiCache()[@2] count] == 3, @"SPKI cache for EC DSA must have been used");
    
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    resetSubjectPublicKeyInfoCache();
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for ECDSA secp256r1");
}

- (void)testVerifyEcDsaSecp384r1
{
    // Create a valid server trust
    SecCertificateRef leafCertificate = [TSKCertificateUtils createCertificateFromDer:@"ssltest42.ssl.symclab.com"];
    SecCertificateRef intermediateCertificate = [TSKCertificateUtils createCertificateFromDer:@"GeoTrust_Intermediate_ECC_EV_SSL_CA"];
    SecCertificateRef intermediateCertificate2 = [TSKCertificateUtils createCertificateFromDer:@"GeoTrust_Primary_CA_G2_ECC"];
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
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"ssltest42.ssl.symclab.com" : @{
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmEcDsaSecp384r1],
                                                                kTSKPublicKeyHashes : @[@"vPtEqrmtAhAVcGtBIep2HIHJ6IlnWQ9vlK50TciLePs=", // Root CA Key
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                                        ]}}});
    
    // Initialize the SPKI cache manually and don't load an existing cache from the filesystem
    initializeSubjectPublicKeyInfoCache();
    XCTAssert([getSpkiCache()[@3] count] == 0, @"SPKI cache for EC DSA 384 must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"ssltest42.ssl.symclab.com",
                                            trustKitConfig[kTSKPinnedDomains][@"ssltest42.ssl.symclab.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"ssltest42.ssl.symclab.com"][kTSKPublicKeyHashes]);
    
    // Ensure the SPKI cache was used; the full certificate chain is three certs and we have to go through all of them to get to the pinned leaf
    XCTAssert([getSpkiCache()[@3] count] == 1, @"SPKI cache for EC DSA 384 must have been used");
    
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    resetSubjectPublicKeyInfoCache();
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins for ECDSA secp384r1");
}


- (void)testVerifyMultipleAlgorithms
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
    trustKitConfig = parseTrustKitConfiguration(@{kTSKSwizzleNetworkDelegates: @NO,
                                                  kTSKPinnedDomains :
                                                      @{@"www.good.com" : @{
                                                                // Define multiple algorithms with the "wrong" one first to ensure the validation still succeeds
                                                                kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048, kTSKAlgorithmRsa4096],
                                                                kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=", // Server Key
                                                                                        @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Fake key
                                                                                        ]}}});
    
    // Initialize the SPKI cache manually and don't load an existing cache from the filesystem
    initializeSubjectPublicKeyInfoCache();
    XCTAssert([getSpkiCache()[@0] count] == 0, @"SPKI cache must be empty");
    XCTAssert([getSpkiCache()[@1] count] == 0, @"SPKI cache must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes]);
    
    // Ensure the SPKI cache was used; the full certificate chain is three certs and we have to go through all of them to get to the pinned leaf
    XCTAssert([getSpkiCache()[@0] count] == 3, @"SPKI cache must have been used");
    XCTAssert([getSpkiCache()[@1] count] == 3, @"SPKI cache must have been used");
    
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    CFRelease(rootCertificate);
    resetSubjectPublicKeyInfoCache();
    
    XCTAssert(verificationResult == TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins with multiple algorithms");
}


@end
