/*
 
 TSKBackgroundReporter.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKBackgroundReporter.h"
#import "TrustKit+Private.h"
#import "TSKPinFailureReport.h"
#import "reporting_utils.h"
#import "TSKReportsRateLimiter.h"

#if TARGET_OS_IPHONE
@import UIKit; // For accessing the IDFV
#endif

// Session identifier for background uploads: <bundle_id>.TSKSimpleReporter
static NSString* kTSKBackgroundSessionIdentifierFormat = @"%@.TSKSimpleReporter";
static NSURLSession *_backgroundSession = nil;
static dispatch_once_t dispatchOnceBackgroundSession;


@interface TSKBackgroundReporter()

@property (nonatomic, strong) NSString * appBundleId;
@property (nonatomic, strong) NSString * appVersion;
@property (nonatomic, strong) NSString * appVendorId;
@property BOOL shouldRateLimitReports;

@end


@implementation TSKBackgroundReporter



- (instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports
{
    self = [super init];
    if (self)
    {
        self.shouldRateLimitReports = shouldRateLimitReports;
        
        // Retrieve the App's information
#if TARGET_OS_IPHONE
        // On iOS use the IDFV
        self.appVendorId = [[[UIDevice currentDevice] identifierForVendor]UUIDString];
#else
        // On OS X, don't use anything for now
        self.appVendorId = @"OS-X";
#endif
    
        CFBundleRef appBundle = CFBundleGetMainBundle();
        self.appBundleId = (__bridge NSString *)CFBundleGetIdentifier(appBundle);
        self.appVersion =  (__bridge NSString *)CFBundleGetValueForInfoDictionaryKey(appBundle, kCFBundleVersionKey);
        
        if (self.appVersion == nil)
        {
            self.appVersion = @"N/A";
        }
        
        if (self.appBundleId == nil)
        {
            // The bundle ID we get is nil if we're running tests on Travis. If the bundle ID is nil, background sessions can't be used
            // backgroundSessionConfigurationWithIdentifier: will throw an exception within dispatch_once() which can't be handled
            // Use a regular session instead
            TSKLog(@"Null bundle ID: we are running the test suite; falling back to a normal session.");
            self.appBundleId = @"N/A";
            self.appVendorId = @"unit-tests";
            
            dispatch_once(&dispatchOnceBackgroundSession, ^{
                _backgroundSession = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]];
            });
        }
        else
        {
            // We're not running unit tests - use a background session
            /*
             Using dispatch_once here ensures that multiple background sessions with the same identifier are not created
             in this instance of the application. If you want to support multiple background sessions within a single process,
             you should create each session with its own identifier.
             */
            dispatch_once(&dispatchOnceBackgroundSession, ^{
                NSURLSessionConfiguration *backgroundConfiguration = nil;
                
                // The API for creating background sessions changed between iOS 7 and iOS 8 and OS X 10.9 and 10.10
#if (TARGET_OS_IPHONE &&__IPHONE_OS_VERSION_MAX_ALLOWED < 80000) || (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MAX_ALLOWED < 1100)
                // iOS 7 or OS X 10.9 as the max SDK: awlays use the deprecated/iOS 7 API
                backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, self.appBundleId]];
#else
                // iOS 8+ or OS X 10.10+ as the max SDK
#if (TARGET_OS_IPHONE &&__IPHONE_OS_VERSION_MIN_REQUIRED < 80000) || (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED < 1100)
                // iOS 7 or OS X 10.9 as the min SDK
                // Try to use the new API if available at runtime
                if (![NSURLSessionConfiguration respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)])
                {
                    // Device runs on iOS 7 or OS X 10.9
                    backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, self.appBundleId]];
                }
                else
#endif
                {
                    // Device runs on iOS 8+ or OS X 10.10+ or min SDK is iOS 8+ or OS X 10.10+
                    backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier: [NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, self.appBundleId]];
                }
#endif
                
                
                
#if TARGET_OS_IPHONE
                // iOS-only settings
                // Do not wake up the App after completing the upload
                backgroundConfiguration.sessionSendsLaunchEvents = NO;
#endif
                
#if (TARGET_OS_IPHONE) || ((!TARGET_OS_IPHONE) && (__MAC_OS_X_VERSION_MIN_REQUIRED >= 1100))
                // On OS X discretionary is only available on 10.10
                backgroundConfiguration.discretionary = YES;
#endif
                _backgroundSession = [NSURLSession sessionWithConfiguration:backgroundConfiguration delegate:self delegateQueue:nil];
            });
        }
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
                       validationResult:(TSKPinValidationResult) validationResult
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
                                                                 validationResult:validationResult
                                                                    appVendorId:self.appVendorId];
    
    
    // Should we rate-limit this report?
    if (self.shouldRateLimitReports && [TSKReportsRateLimiter shouldRateLimitReport:report])
    {
        // We recently sent the exact same report; do not send this report
        TSKLog(@"Pin failure report for %@ was not sent due to rate-limiting", serverHostname);
        return;
    }
    
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
        TSKLog(@"Background upload - task %@ completed successfully; pinning failure report sent", task);
    }
    else
    {
        TSKLog(@"Background upload - task %@ completed with error: %@ (code %ld)", task, [error localizedDescription], (long)error.code);
    }
}

@end

