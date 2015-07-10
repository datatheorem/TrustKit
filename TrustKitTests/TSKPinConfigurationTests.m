/*
 
 TSKPinConfigurationTests.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"
#import "ssl_pin_verifier.h"
#import "public_key_utils.h"



@interface TSKPinConfigurationTests : XCTestCase
{
    
}
@end

@implementation TSKPinConfigurationTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


// Pin to only one key and ensure it fails; TrustKit requires at least two pins (which should include a backup pin)
- (void)testPinOnePublicKey
{
    XCTAssertThrows(parseTrustKitArguments(@{@"www.good.com" : @{
                                                     kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                     kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                             ]}}),
                    @"Configuration with one pin only must be rejected");
}



- (void)testGetConfigurationPinningEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="]}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"Did not receive a configuration for a pinned domain");
}


- (void)testGetConfigurationPinningDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    // Ensure www.datatheorem.com gets no configuration
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.datatheorem.com", trustKitConfig);
    XCTAssert(serverConfigKey == nil, @"Received a configuration a non-pinned domain");
}


- (void)testIncludeSubdomainsEnabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKIncludeSubdomains : @YES,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    // Ensure www.good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSameDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKIncludeSubdomains : @YES,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    // Ensure good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledSubSubDomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                      kTSKIncludeSubdomains : @YES,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"sub.www.good.com.www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledNotSubdomain
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKIncludeSubdomains : @YES,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    // Corner case to ensure two different domains with similar strings don't get returned as subdomains
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"good.com.otherdomain.com", trustKitConfig);
    XCTAssertNil(serverConfigKey);
}


- (void)testIncludeSubdomainsDisabled
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKIncludeSubdomains : @NO,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]}});
    
    // Ensure www.good.com does not get the configuration set for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert(serverConfigKey == nil, @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsEnabledAndSpecificConfiguration
{
    NSDictionary *trustKitConfig;
    trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                      kTSKIncludeSubdomains : @YES,
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                      kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY=",
                                                                              @"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                              ]},
                                              @"www.good.com": @{
                                                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                      kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0=",
                                                                              @"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0="
                                                                              ]}});
    
    // Ensure the configuration specific to www.good.com takes precedence over the more general config for good.com
    NSString *serverConfigKey = getPinningConfigurationKeyForDomain(@"www.good.com", trustKitConfig);
    XCTAssert([serverConfigKey isEqualToString:@"www.good.com"], @"IncludeSubdomains took precedence over a more specialized configuration");
}

@end