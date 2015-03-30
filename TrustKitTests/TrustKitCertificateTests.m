//
//  TrustKitCertificateTests.m
//  TrustKit
//
//  Created by Eric on 30/03/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "TrustKit.h"
#import "TrustKit+Private.h"
#import "TrustKitTestCertificates.h"

@interface TrustKitServerTests : XCTestCase
@end


@interface TrustKitCertificateTests : XCTestCase
{

}
@end

@implementation TrustKitCertificateTests

- (void)setUp {
    [super setUp];



}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];

}

- (void)testExample {

    [TKSettings setPublicKeyPins:@{
            @"www.good.com" : @[
                    @"4d012d74c6e6c058185227cce0b0c5fb1804b5dd33ebd98f1a6929d35e1de996", //Server key
                    @"921288e9a7b89a2704bd7ef8301fc1678bb5e560961973c3e868e0ea221155e1", //Intermediate key
                    @"890324e289eb249cff9f05b5c02511d1872c877a2685b33e3ea304c0da1ffcad" //CA key
            ]
    } shouldOverwrite:YES];

    SecPolicyRef policy = SecPolicyCreateSSL(true, NULL);

    CFDataRef rootData = CFDataCreate(kCFAllocatorDefault, ca_cert_der, (CFIndex)ca_cert_der_len);
    SecCertificateRef root = SecCertificateCreateWithData(kCFAllocatorDefault, rootData);
    CFRelease(rootData);

    CFDataRef chainData = CFDataCreate(kCFAllocatorDefault, ca_chain_cert_der, (CFIndex)ca_chain_cert_der_len);
    SecCertificateRef chain = SecCertificateCreateWithData(kCFAllocatorDefault, chainData);
    CFRelease(chainData);

    CFDataRef leafData = CFDataCreate(kCFAllocatorDefault, www_good_com_cert_der, (CFIndex)www_good_com_cert_der_len);
    SecCertificateRef leaf = SecCertificateCreateWithData(kCFAllocatorDefault, leafData);
    CFRelease(leafData);

    SecCertificateRef certArray[2] = { chain, leaf };
    CFArrayRef certs = CFArrayCreate(NULL, (const void **)certArray, 2, NULL);
    SecTrustRef trust;

    if(SecTrustCreateWithCertificates(certs, policy, &trust) == errSecSuccess)
    {
        SecCertificateRef rootArray[1] = { root };
        CFArrayRef rootCerts = CFArrayCreate(NULL, (const void **)rootArray, 1, NULL);

        if(SecTrustSetAnchorCertificates(trust, rootCerts) == errSecSuccess)
        {
            NSLog(@"verifyCertificatePin returned: %d", verifyCertificatePin(trust, @"www.good.com"));
        }

        CFRelease(rootArray);

    }

    CFRelease(root);
    CFRelease(leaf);
    CFRelease(chain);
    CFRelease(certs);
    CFRelease(trust);
    CFRelease(policy);


}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
