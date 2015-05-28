//
//  TSKPinConfigurationTests.m
//  TrustKit
//
//  Created by Alban Diquet on 5/28/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

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


- (void)testGetConfigurationPinningEnabled
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"www.good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="]}});
    
    NSDictionary *serverConfig = getPinningConfigurationForDomain(@"www.good.com", trustKitConfig);
    
    XCTAssert(serverConfig != nil, @"Did not receive a configuration for a pinned domain");
    XCTAssert(serverConfig == trustKitConfig[@"www.good.com"], @"Did not receive a configuration for a pinned domain");
}


- (void)testGetConfigurationPinningDisabled
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                                            ]}});
    
    // Ensure www.datatheorem.com gets no configuration
    NSDictionary *serverConfig = getPinningConfigurationForDomain(@"www.datatheorem.com", trustKitConfig);
    
    XCTAssert(serverConfig == nil, @"Received a configuration a non-pinned domain");
}


- (void)testIncludeSubdomainsEnabled
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                                            ]}});
    
    // Ensure www.good.com gets the configuration set for good.com as includeSubdomains is enabled
    NSDictionary *serverConfig = getPinningConfigurationForDomain(@"www.good.com", trustKitConfig);
    
    XCTAssert(serverConfig != nil, @"IncludeSubdomains did not work");
    XCTAssert(serverConfig == trustKitConfig[@"good.com"], @"IncludeSubdomains did not work");
}


- (void)testIncludeSubdomainsDisabled
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @NO,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                                            ]}});
    
    // Ensure www.good.com does not get the configuration set for good.com
    NSDictionary *serverConfig = getPinningConfigurationForDomain(@"www.good.com", trustKitConfig);
    
    XCTAssert(serverConfig == nil, @"IncludeSubdomains did not work");
}

- (void)testIncludeSubdomainsEnabledAndSpecificConfiguration
{
    NSDictionary *trustKitConfig = parseTrustKitArguments(@{@"good.com" : @{
                                                                    kTSKIncludeSubdomains : @YES,
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa4096],
                                                                    kTSKPublicKeyHashes : @[@"TQEtdMbmwFgYUifM4LDF+xgEtd0z69mPGmkp014d6ZY="
                                                                                            ]},
                                                            @"www.good.com": @{
                                                                    kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                                                                    kTSKPublicKeyHashes : @[@"iQMk4onrJJz/nwW1wCUR0Ycsh3omhbM+PqMEwNof/K0="
                                                                                            ]}});
    
    // Ensure the configuration specific to www.good.com takes precedence over the more general config for good.com
    NSDictionary *serverConfig = getPinningConfigurationForDomain(@"www.good.com", trustKitConfig);
    
    XCTAssert(serverConfig != nil, @"IncludeSubdomains did not work");
    XCTAssert(serverConfig == trustKitConfig[@"www.good.com"], @"IncludeSubdomains took precedence over a more specialized configuration");
}

@end