//
//  TSKSimpleBackgroundReporter.m
//  TrustKit
//
//  Created by Angela Chow on 5/14/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleBackgroundReporter.h"
#import "TrustKit+Private.h"
#import "TSKPinFailureReport.h"


// Session identifier for background uploads: <bundle id>.TSKSimpleReporter
static NSString* backgroundSessionIdentifierFormat = @"%@.TSKSimpleReporter";


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

        // The API for creating background sessions changed between iOS 7 and iOS 8 and OS X 10.9 and 10.10
#if (TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MIN_REQUIRED < 80000) || (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED < 101000)
        // iOS 7 or OS X 10.9
        backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:backgroundSessionIdentifierFormat, self.appBundleId]];
#else
        // iOS 8+ or OS X 10.10+
        backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier: [NSString stringWithFormat:backgroundSessionIdentifierFormat, self.appBundleId]];
#endif
    
        backgroundConfiguration.discretionary = YES;
#if TARGET_OS_IPHONE
        backgroundConfiguration.sessionSendsLaunchEvents = NO;
        backgroundConfiguration.sharedContainerIdentifier = [NSString stringWithFormat:backgroundSessionIdentifierFormat, self.appBundleId];
#endif
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
    // Create the pin validation failure report
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppVersion:self.appVersion
                                                                   notedHostname:pinnedDomainStr
                                                                  serverHostname:hostnameStr
                                                                            port:port
                                                               includeSubdomains:includeSubdomains
                                                       validatedCertificateChain:validatedCertificateChain
                                                                       knownPins:knownPins];
    
    // Create the HTTP request
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportingURL];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    
    // Create a temporary file for storing the JSON data in ~/tmp
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *tmpFileURL = [[tmpDirURL URLByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]] URLByAppendingPathExtension:@"tsk-report"];
    TSKLog(@"fileURL: %@", [tmpFileURL path]);
    
    // Write the JSON report data to the temporary file
    if (!([[report json] writeToFile:[tmpFileURL path] atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    // Pass the URL and the temporary file to the background upload task and start uploading
    NSURLSessionUploadTask *uploadTask = [self.session uploadTaskWithRequest:request fromFile:tmpFileURL];
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

