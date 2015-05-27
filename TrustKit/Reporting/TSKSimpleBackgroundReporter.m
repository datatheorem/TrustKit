//
//  TSKSimpleBackgroundReporter.m
//  TrustKit
//
//  Created by Angela Chow on 5/14/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleBackgroundReporter.h"
#import "TrustKit+Private.h"

@interface TSKSimpleBackgroundReporter()

@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic) BOOL isTSKSimpleReporterInitialized;
@property (nonatomic) NSURLSession *session;

@end


@implementation TSKSimpleBackgroundReporter


/*
 * Initialize the reporter with the app's bundle id and app version
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion
{
    if (_isTSKSimpleReporterInitialized == YES)
    {
        // Reporter should only be initialized once
        [NSException raise:@"TrustKit Reporter already initialized" format:@"Reporter was already initialized with the following appBundleId: %@", appBundleId];
    }
    
    self = [super init];
    if (self)
    {
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
        self.session = [self backgroundSession];

        self.isTSKSimpleReporterInitialized = YES;
        
    }
    return self;
}

- (NSURLSession *)backgroundSession
{
    
    /*
     Using disptach_once here ensures that multiple background sessions with the same identifier are not created in this instance of the application. If you want to support multiple background sessions within a single process, you should create each session with its own identifier.
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
        backgroundConfiguration.discretionary = YES;
        backgroundConfiguration.sessionSendsLaunchEvents = NO;

        session = [NSURLSession sessionWithConfiguration:backgroundConfiguration delegate:self delegateQueue:nil];
    });
    return session;
}

/*
  Pin validation failed for a connection to a pinned domain
  In this implementation for a simple background reporter, we're just going to send out the report upon each failure
  in a background task
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
    
    //make a file name to write the data to using the tmp directory:
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *fileURL = [[tmpDirURL URLByAppendingPathComponent:@"TSKReport"] URLByAppendingPathExtension:currentTimeStr];
    TSKLog(@"fileURL: %@", [fileURL path]);
    
    //write postdata to file as we can only use background upload task with file
    if (!([postData writeToFile:[fileURL path] atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    NSURLSessionUploadTask *uploadTask  = [self.session uploadTaskWithRequest: request fromFile: fileURL];
    [uploadTask resume];
    
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
    
    TSKLog(@"totalBytesSent:%lld", totalBytesSent);
    TSKLog(@"totalBytesExpectedToSend:%lld", totalBytesExpectedToSend);
    
}


- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    
    if (error == nil)
    {
        TSKLog(@"Task: %@ completed successfully", task);
    }
    else
    {
        TSKLog(@"Task: %@ completed with error: %@", task, [error localizedDescription]);
        TSKLog(@"Task: error.code: %ld", (long)error.code);
        
    }
}

@end

