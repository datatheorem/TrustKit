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


// Session identifier for background uploads: <bundle_id>.TSKSimpleReporter
static NSString* backgroundSessionIdentifierFormat = @"%@.TSKSimpleReporter";


@interface TSKSimpleBackgroundReporter()

@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic) NSURLSession *session;

@end


@implementation TSKSimpleBackgroundReporter


- (instancetype)initWithAppBundleId:(NSString *)appBundleId
                         appVersion:(NSString *)appVersion
{
    self = [super init];
    if (self)
    {
        if ((appBundleId == nil) || ([appBundleId length] == 0))
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appBundleId"];
        }
        self.appBundleId = appBundleId;
        
        if ((appVersion == nil) || ([appVersion length] == 0))
        {
            [NSException raise:@"TrustKit Simple Reporter configuration invalid"
                        format:@"Reporter was given empty appVersion"];
        }
        self.appVersion = appVersion;
        
        self.session = [self backgroundSession];
    }
    return self;
}

- (NSURLSession *)backgroundSession
{
    /*
     Using disptach_once here ensures that multiple background sessions with the same identifier are not created in this instance of the application. If you want to support multiple background sessions within a single process, you should create each session with its own identifier.
     */
    __block NSURLSession *session = nil;
    dispatch_once_t onceToken;
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

#if TARGET_OS_IPHONE
        // iOS-only settings
        // Do not wake up the App after completing the upload
        backgroundConfiguration.sessionSendsLaunchEvents = NO;
#endif

        backgroundConfiguration.discretionary = YES;
        session = [NSURLSession sessionWithConfiguration:backgroundConfiguration delegate:self delegateQueue:nil];
    });
    return session;
}

/*
  Pin validation failed for a connection to a pinned domain
  In this implementation for a simple background reporter, we're just going to send out the report upon each failure
  in a background task
 */

- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                          notedHostname:(NSString *) notedHostname
                              reportURI:(NSURL *) reportURI
                      includeSubdomains:(BOOL) includeSubdomains
              validatedCertificateChain:(NSArray *) certificateChain
                              knownPins:(NSArray *) knownPins
{
    // Default port to 443 if not specified
    if (serverPort == nil)
    {
        serverPort = [NSNumber numberWithInt:443];
    }
    
    if (reportURI == nil)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportingURL: %@ for domain %@",
         reportURI, notedHostname];
    }

    // Create the pin validation failure report
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppBundleId:self.appBundleId
                                                                       appVersion:self.appVersion
                                                                    notedHostname:notedHostname
                                                                         hostname:serverHostname
                                                                             port:serverPort
                                                                         dateTime:[NSDate date] // Use the current time
                                                                includeSubdomains:includeSubdomains
                                                        validatedCertificateChain:certificateChain
                                                                        knownPins:knownPins];
    
    // Create the HTTP request
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportURI];
    [request setHTTPMethod:@"POST"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    
    // Create a temporary file for storing the JSON data in ~/tmp
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *tmpFileURL = [[tmpDirURL URLByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]] URLByAppendingPathExtension:@"tsk-report"];
    TSKLog(@"Report created at: %@", [tmpFileURL path]);
    
    // Write the JSON report data to the temporary file
    if (!([[report json] writeToFile:[tmpFileURL path] atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    // Pass the URL and the temporary file to the background upload task and start uploading
    NSURLSessionUploadTask *uploadTask = [self.session uploadTaskWithRequest:request fromFile:tmpFileURL];
    [uploadTask resume];
}


- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    if (error == nil)
    {
        TSKLog(@"Background upload - task %@ completed successfully", task);
    }
    else
    {
        TSKLog(@"Background upload - task %@ completed with error: %@ (code %ld)", task, [error localizedDescription], (long)error.code);
    }
}

@end

