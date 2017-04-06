/*
 
 TSKPublicKeyAlgorithmTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "../TrustKit/TSKTrustKitConfig.h"
#import "../TrustKit/parse_configuration.h"

#import "../TrustKit/Pinning/ssl_pin_verifier.h"
#import "../TrustKit/Pinning/TSKSPKIHashCache.h"
#import "../TrustKit/Reporting/reporting_utils.h"

#import "TSKCertificateUtils.h"


@interface TSKSPKIHashCache (TestSupport)
- (void)resetSubjectPublicKeyInfoDiskCache;
@end


@interface TSKPublicKeyAlgorithmTests : XCTestCase
@end

@implementation TSKPublicKeyAlgorithmTests
{
    TSKSPKIHashCache *spkiCache;
}

- (void)setUp
{
    [super setUp];
    spkiCache = [TSKSPKIHashCache new];
    [spkiCache resetSubjectPublicKeyInfoDiskCache];
}

- (void)tearDown
{
    spkiCache = nil;
    [super tearDown];
}


- (void)testExtractRsa2048
{
    // Ensure a RSA 2048 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.globalsign.com"];

    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate publicKeyAlgorithm:TSKPublicKeyAlgorithmRsa2048];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];

    XCTAssertEqualObjects(spkiPin, @"NDCIt6TrQnfOk+lquunrmlPQB3K/7CLOCmSS5kW+KCc=");
    CFRelease(certificate);
}


- (void)testExtractRsa4096
{
    // Ensure a RSA 4096 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.good.com"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate publicKeyAlgorithm:TSKPublicKeyAlgorithmRsa4096];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=");
    CFRelease(certificate);
}


- (void)testExtractEcDsaSecp256r1
{
    // Ensure a secp256r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"www.cloudflare.com"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate publicKeyAlgorithm:TSKPublicKeyAlgorithmEcDsaSecp256r1];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"Gc7EN2acfkbE0dUOAd34tr1XLr+JdkTiTrMAfhESQHI=");
    CFRelease(certificate);
}


- (void)testExtractEcDsaSecp384r1
{
    // Ensure a secp384r1 key is properly extracted from its certificate
    SecCertificateRef certificate = [TSKCertificateUtils createCertificateFromDer:@"GeoTrust_Primary_CA_G2_ECC"];
    
    NSData *spkiHash = [spkiCache hashSubjectPublicKeyInfoFromCertificate:certificate publicKeyAlgorithm:TSKPublicKeyAlgorithmEcDsaSecp384r1];
    NSString *spkiPin = [spkiHash base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    
    XCTAssertEqualObjects(spkiPin, @"vPtEqrmtAhAVcGtBIep2HIHJ6IlnWQ9vlK50TciLePs=");
    CFRelease(certificate);
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
    XCTAssertEqual([spkiCache.getSpkiCache[@0] count], 0UL, @"SPKI cache must be empty");
    XCTAssertEqual([spkiCache.getSpkiCache[@1] count], 0UL, @"SPKI cache must be empty");
    
    TSKPinValidationResult verificationResult = TSKPinValidationResultFailed;
    verificationResult = verifyPublicKeyPin(trust,
                                            @"www.good.com",
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyAlgorithms],
                                            trustKitConfig[kTSKPinnedDomains][@"www.good.com"][kTSKPublicKeyHashes],
                                            spkiCache);
    
    // Ensure the SPKI cache was used; the full certificate chain is three certs and we have to go through all of them to get to the pinned leaf
    XCTAssertEqual([spkiCache.getSpkiCache[@0] count], 3UL, @"SPKI cache must have been used");
    XCTAssertEqual([spkiCache.getSpkiCache[@1] count], 3UL, @"SPKI cache must have been used");
    
    CFRelease(trust);
    CFRelease(leafCertificate);
    CFRelease(intermediateCertificate);
    CFRelease(rootCertificate);
    
    XCTAssertEqual(verificationResult, TSKPinValidationResultSuccess, @"Validation must pass against valid public key pins with multiple algorithms");
}


@end
