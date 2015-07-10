/*
 
 TSKSimpleBackgroundReporter.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKSimpleBackgroundReporter.h"
#import "TrustKit+Private.h"
#import "TSKPinFailureReport.h"
#import "reporting_utils.h"

// Session identifier for background uploads: <bundle_id>.TSKSimpleReporter
static NSString* kTSKBackgroundSessionIdentifierFormat = @"%@.TSKSimpleReporter";
static NSURLSession *_backgroundSession = nil;
static dispatch_once_t dispatchOnceBackgroundSession;


@interface TSKSimpleBackgroundReporter()

@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
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
            self.appBundleId = @"N/A";
        }
        else
        {
            self.appBundleId = appBundleId;
        }
        
        if ((appVersion == nil) || ([appVersion length] == 0))
        {
            self.appVersion = @"N/A";
        }
        else
        {
            self.appVersion = appVersion;
        }
        
        /*
         Using dispatch_once here ensures that multiple background sessions with the same identifier are not created 
         in this instance of the application. If you want to support multiple background sessions within a single process, 
         you should create each session with its own identifier.
         */
        dispatch_once(&dispatchOnceBackgroundSession, ^{
            NSURLSessionConfiguration *backgroundConfiguration = nil;
            
            // The API for creating background sessions changed between iOS 7 and iOS 8 and OS X 10.9 and 10.10
            //#if (TARGET_OS_IPHONE &&__IPHONE_OS_VERSION_MIN_REQUIRED < 80000) || (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED < 1090)
            if (![NSURLSessionConfiguration respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)])
            {
                // iOS 7 or OS X 10.9
                backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, self.appBundleId]];
            }
            else
                //#endif
            {
                // iOS 8+ or OS X 10.10+
                backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier: [NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, self.appBundleId]];
            }
            
            
#if TARGET_OS_IPHONE
            // iOS-only settings
            // Do not wake up the App after completing the upload
            backgroundConfiguration.sessionSendsLaunchEvents = NO;
#endif
            
            backgroundConfiguration.discretionary = YES;
            _backgroundSession = [NSURLSession sessionWithConfiguration:backgroundConfiguration delegate:self delegateQueue:nil];
        });
    }
    return self;
}


/*
  Pin validation failed for a connection to a pinned domain
  In this implementation for a simple background reporter, we're just going to send out the report upon each failure
  in a background task
 */
- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                                  trust:(SecTrustRef) serverTrust
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                              knownPins:(NSArray *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult;
{
    // Default port to 0 if not specified
    if (serverPort == nil)
    {
        serverPort = [NSNumber numberWithInt:0];
    }
    
    if (reportURIs == nil)
    {
        [NSException raise:@"TrustKit Simple Background Reporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportURIs: %@ for domain %@",
         reportURIs, notedHostname];
    }
    
    // Create the pin validation failure report
    NSArray *certificateChain = convertTrustToPemArray(serverTrust);
    NSArray *formattedPins = convertPinsToHpkpPins(knownPins);
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppBundleId:self.appBundleId
                                                                       appVersion:self.appVersion
                                                                    notedHostname:notedHostname
                                                                         hostname:serverHostname
                                                                             port:serverPort
                                                                         dateTime:[NSDate date] // Use the current time
                                                                includeSubdomains:includeSubdomains
                                                        validatedCertificateChain:certificateChain
                                                                        knownPins:formattedPins
                                                                 validationResult:validationResult];
    
    // Create a temporary file for storing the JSON data in ~/tmp
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *tmpFileURL = [[tmpDirURL URLByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]] URLByAppendingPathExtension:@"tsk-report"];
    TSKLog(@"Report created at: %@", [tmpFileURL path]);
    
    // Write the JSON report data to the temporary file
    if (!([[report json] writeToFile:[tmpFileURL path] atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    
    // Create the HTTP request for all the configured report URIs and send it
    for (NSURL *reportUri in reportURIs)
    {
        NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:reportUri];
        [request setHTTPMethod:@"POST"];
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        
        // Pass the URL and the temporary file to the background upload task and start uploading
        NSURLSessionUploadTask *uploadTask = [_backgroundSession uploadTaskWithRequest:request
                                                                              fromFile:tmpFileURL];
        [uploadTask resume];
    }
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

