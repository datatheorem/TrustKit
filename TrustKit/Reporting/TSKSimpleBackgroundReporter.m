//
//  TSKSimpleBackgroundReporter.m
//  TrustKit
//
//  Created by Angela Chow on 5/14/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleBackgroundReporter.h"
#import "TSKAppDelegate.h"

@interface TSKSimpleBackgroundReporter()


@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic) BOOL isTSKSimpleReporterInitialized;

@end


@implementation TSKSimpleBackgroundReporter


/*
 * Initialize the reporter with the app's bundle id and app version
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion
{
    
    self = [super init];
    if (self) {
        // Custom initialization
        if ([appBundleId length] == 0)
        {
            [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                        format:@"Reporter was given empty appBundleId"];
        }
        self.appBundleId = appBundleId;
        
        if ([appVersion length] == 0)
        {
            [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                        format:@"Reporter was given empty appVersion"];
        }
        self.appVersion = appVersion;
        self.isTSKSimpleReporterInitialized = YES;
        
    }
    return self;
}

- (NSURLSession *)backgroundSession
{
    
    /*
     * Using disptach_once here ensures that multiple background sessions with the same identifier are not created in this
     * instance of the application.
     */
    static NSURLSession *session = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        NSURLSessionConfiguration *backgroundConfiguration;
        if ([[[UIDevice currentDevice] systemVersion] floatValue] >=8.0f)
        {
            // starting iOS 8, backgroundSessionConfigurationWithIdentifier is used instead of backgroundSessionConfiguration
            backgroundConfiguration =
            [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier:
             [NSString stringWithFormat:@"%@.%@", self.appBundleId, @"TSKSimpleBgdReporter" ]];
        }
        else
        {
            backgroundConfiguration =
            [NSURLSessionConfiguration backgroundSessionConfiguration:
             [NSString stringWithFormat:@"%@.%@", self.appBundleId, @"TSKSimpleBgdReporter" ]];
        }
        session = [NSURLSession sessionWithConfiguration:backgroundConfiguration delegate:self delegateQueue:nil];
    });
    
    return session;
}

/*
 * Pin validation failed for a connection to a pinned domain
 * In this implementation for a simple background reporter, we're just going to send out the report upon each failure
 * in a background task
 */
- (void) pinValidationFailed:(NSString *) pinnedDomainStr
              serverHostname:(NSString *) hostnameStr
                  serverPort:(NSNumber *) port
                reportingURL:(NSString *) reportingURLStr
           includeSubdomains:(Boolean) includeSubdomains
            certificateChain:(NSArray *) validatedCertificateChain
                expectedPins:(NSArray *) knownPins
{
    
    if (self.isTSKSimpleReporterInitialized == NO)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was not initialized with appid and appversion yet"];
        
    }
    
    if ([pinnedDomainStr length] == 0)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given empty pinnedDomainStr"];
    }
    
    if ([hostnameStr length] == 0)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given empty serverHostname"];
    }
    
    //default port to 443 if not specified
    if (port == nil)
    {
        port = [NSNumber numberWithInt:443];
    }
    
    NSURL *reportingURL = [NSURL URLWithString:reportingURLStr];
    if (reportingURL == nil)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportingURL: %@ for domain %@",
         reportingURLStr, pinnedDomainStr];
    }
    
    if ([validatedCertificateChain count] == 0)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given empty certificateChain"];
        
    }
    
    if ([knownPins count] == 0)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given empty expectedPins"];
        
    }
    
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportingURL];
    
    NSDate *currentTime = [NSDate date];
    NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
    [dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
    [dateFormatter setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"UTC"]];
    NSString *currentTimeStr = [dateFormatter stringFromDate: currentTime];
    
    NSDictionary *requestData = [[NSDictionary alloc] initWithObjectsAndKeys:
                                 self.appBundleId, @"app-bundle-id",
                                 self.appVersion, @"app-version",
                                 currentTimeStr, @"date-time",
                                 hostnameStr, @"hostname",
                                 port, @"port",
                                 [NSNumber numberWithBool:includeSubdomains], @"include-subdomains",
                                 pinnedDomainStr, @"noted-hostname",
                                 validatedCertificateChain, @"validated-certificate-chain",
                                 knownPins, @"known-pins",
                                 nil];
    
    NSError *error;
    NSData *postData = [NSJSONSerialization dataWithJSONObject:requestData options:0 error:&error];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    [request setHTTPBody: postData];
    
    //make a file name to write the data to using the tmp directory:
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *fileURL = [[tmpDirURL URLByAppendingPathComponent:@"TSKReport"] URLByAppendingPathExtension:@"tmp"];
    NSLog(@"fileURL: %@", [fileURL path]);
    
    //Write postdata to file as we can only use background upload task with file
    if (!([postData writeToFile:[fileURL path] atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    
    NSURLSessionUploadTask *postDataTask = [[self backgroundSession] uploadTaskWithRequest: request fromFile: fileURL];
    
    [postDataTask resume];
    
    
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data
{
    NSString * str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    NSLog(@"Received String %@",str);
    
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend
{
    
    /*
     Report progress on the task.
     If you created more than one task, you might keep references to them and report on them individually.
     */
    NSLog(@"totalBytesSent:%lld", totalBytesSent);
    NSLog(@"totalBytesSent:%lld", totalBytesExpectedToSend);

}
    



- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    
    if (error == nil)
    {
        NSLog(@"Task: %@ completed successfully", task);
    }
    else
    {
        NSLog(@"Task: %@ completed with error: %@", task, [error localizedDescription]);
    }
    
}

/*
 If an application has received an -application:handleEventsForBackgroundURLSession:completionHandler: message, the session delegate will receive this message to indicate that all messages previously enqueued for this session have been delivered. At this time it is safe to invoke the previously stored completion handler, or to begin any internal updates that will result in invoking the completion handler.
 */
- (void)URLSessionDidFinishEventsForBackgroundURLSession:(NSURLSession *)session
{
    TSKAppDelegate *appDelegate = (TSKAppDelegate *) [[UIApplication sharedApplication] delegate];
    if (appDelegate.backgroundSessionCompletionHandler) {
        void (^completionHandler)() = appDelegate.backgroundSessionCompletionHandler;
        appDelegate.backgroundSessionCompletionHandler = nil;
        completionHandler();
    }
    
    NSLog(@"All tasks are finished");
}



@end

