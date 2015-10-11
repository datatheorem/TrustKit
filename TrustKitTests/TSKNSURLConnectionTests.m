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

- (void)testNSURLConnection {
    
    NSDictionary *trustKitConfig =
    @{
      kTSKPinnedDomains :
          @{
              @"www.yahoo.com" : @{
                      kTSKPublicKeyAlgorithms : @[kTSKAlgorithmRsa2048],
                      kTSKPublicKeyHashes : @[@"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=", // CA key
                                              @"HXXQgxueCIU5TTLHob/bPbwcKOKw6DkfsTWYHbxbqTY=" // CA key
                                              ]}}};
    
    [TrustKit initializeWithConfiguration:trustKitConfig];
    
    
    
    // NSURLConnection is deprecated
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    
    XCTestExpectation *expectation = [self expectationWithDescription:@"TestNSURLConnectionDelegate"];
    TestNSURLConnectionDelegate* delegate = [[TestNSURLConnectionDelegate alloc] initWithExpectation:expectation];
    NSURLConnection *connection = [[NSURLConnection alloc]
                                   initWithRequest:[NSURLRequest requestWithURL:
                                                    [NSURL URLWithString:@"https://www.reddit.com/normal"]]
                                   delegate:delegate];
    [connection start];
    
    
    // Run other methods that we swizzle to display a warning, to ensure they don't crash
    XCTestExpectation *expectation2 = [self expectationWithDescription:@"Asynchronous request"];
    [NSURLConnection sendAsynchronousRequest:[NSURLRequest requestWithURL:
                                              [NSURL URLWithString:@"https://www.datatheorem.com/test"]]
                                       queue:[NSOperationQueue mainQueue]
                           completionHandler:^(NSURLResponse *response, NSData *data, NSError *error) {
                               [expectation2 fulfill];
                           }];
    
    [NSURLConnection sendSynchronousRequest:[NSURLRequest requestWithURL:
                                             [NSURL URLWithString:@"https://www.datatheorem.com/test"]]
                          returningResponse:nil error:nil];
#pragma GCC diagnostic pop
    
    
    [self waitForExpectationsWithTimeout:5.0 handler:^(NSError *error) {
        if (error) {
            NSLog(@"Timeout Error: %@", error);
        }
    }];
}



@end
