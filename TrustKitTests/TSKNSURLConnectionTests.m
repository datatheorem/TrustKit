//
//  TSKNSURLConnectionTests.m
//  TrustKit
//
//  Created by Alban Diquet on 10/11/15.
//  Copyright © 2015 TrustKit. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "TrustKit+Private.h"


@interface TestNSURLConnectionDelegate : NSObject <NSURLConnectionDataDelegate>
{
    XCTestExpectation *testExpectation;
}
- (instancetype)initWithExpectation:(XCTestExpectation *)expectation;
- (void)connectionDidFinishLoading:(NSURLConnection *)connection;
- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error;
- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse;
- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response;
@end


@implementation TestNSURLConnectionDelegate {
}

- (instancetype)initWithExpectation:(XCTestExpectation *)expectation
{
    self = [super init];
    if (self)
    {
        testExpectation = expectation;
    }
    return self;
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection {}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    NSLog(@"%@ - failed: %@", NSStringFromClass([self class]), error);
    [testExpectation fulfill];
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    NSLog(@"%@ - received %lu bytes", NSStringFromClass([self class]), (unsigned long)[data length]);
    [testExpectation fulfill];
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse
{
    return cachedResponse;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response
{
    NSLog(@"%@ - success: %@", NSStringFromClass([self class]), [[response URL] host]);
    [testExpectation fulfill];
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse
{
    NSLog(@"%@ - redirect: %@", NSStringFromClass([self class]), [[request URL] host]);
    [testExpectation fulfill];
    return request;
}

@end


@interface TSKNSURLConnectionTests : XCTestCase

@end

@implementation TSKNSURLConnectionTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.datatheorem.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=", // CA key
                                              @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=" // CA key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"High Expectations"];
    
    // NSURLConnection is deprecated
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    
    TestNSURLConnectionDelegate* deleg2 = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    NSURLConnection *conn2 = [[NSURLConnection alloc]
                              initWithRequest:[NSURLRequest requestWithURL:
                                               [NSURL URLWithString:@"https://www.reddit.com/normal"]]
                              delegate:deleg2];
    [conn2 start];
#pragma GCC diagnostic pop
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
}




@end
