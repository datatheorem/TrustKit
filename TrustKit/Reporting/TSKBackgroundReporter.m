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
#else
#import "osx_vendor_id.h"  // Home-made IDFV for OS X
#endif



// Session identifier for background uploads: <bundle_id>.TSKBackgroundReporter
static NSString *kTSKBackgroundSessionIdentifierFormat = @"%@.TSKBackgroundReporter";
static NSURLSession *_backgroundSession = nil;
static dispatch_once_t dispatchOnceBackgroundSession;


@interface TSKBackgroundReporter()

@property (nonatomic, strong) NSString *appBundleId;
@property (nonatomic, strong) NSString *appVersion;
@property (nonatomic, strong) NSString *appVendorId;
@property (nonatomic, strong) NSString *appPlatform;
@property BOOL shouldRateLimitReports;


@end


@implementation TSKBackgroundReporter

#pragma mark Public methods

- (instancetype)initAndRateLimitReports:(BOOL)shouldRateLimitReports
{
    self = [super init];
    if (self)
    {
        _shouldRateLimitReports = shouldRateLimitReports;
        
        // Retrieve the App's information
#if TARGET_OS_IPHONE
        _appPlatform = @"IOS";
#else
        _appPlatform = @"OSX";
#endif
        
        CFBundleRef appBundle = CFBundleGetMainBundle();
        _appBundleId = (__bridge NSString *)CFBundleGetIdentifier(appBundle);
        _appVersion =  (__bridge NSString *)CFBundleGetValueForInfoDictionaryKey(appBundle, kCFBundleVersionKey);
        
        if (_appVersion == nil)
        {
            _appVersion = @"N/A";
        }
        
        if (_appBundleId == nil)
        {
            // The bundle ID we get is nil if we're running tests on Travis. If the bundle ID is nil, background sessions can't be used
            // backgroundSessionConfigurationWithIdentifier: will throw an exception within dispatch_once() which can't be handled
            // Use a regular session instead
            TSKLog(@"Null bundle ID: we are running the test suite; falling back to a normal session.");
            _appBundleId = @"N/A";
            _appVendorId = @"unit-tests";
            
            dispatch_once(&dispatchOnceBackgroundSession, ^{
                _backgroundSession = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                                   delegate:self
                                                              delegateQueue:nil];
            });
        }
        else
        {
            // Get the vendor identifier
#if TARGET_OS_IPHONE
            // On iOS use the IDFV
            _appVendorId = [[[UIDevice currentDevice] identifierForVendor]UUIDString];
#else
            // On OS X we use a hash of the mac address and bundle ID
            _appVendorId = osx_identifier_for_vendor(_appBundleId);
#endif
            
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
                backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, _appBundleId]];
#else
                // iOS 8+ or OS X 10.10+ as the max SDK
#if (TARGET_OS_IPHONE &&__IPHONE_OS_VERSION_MIN_REQUIRED < 80000) || (!TARGET_OS_IPHONE && __MAC_OS_X_VERSION_MIN_REQUIRED < 1100)
                // iOS 7 or OS X 10.9 as the min SDK
                // Try to use the new API if available at runtime
                if (![NSURLSessionConfiguration respondsToSelector:@selector(backgroundSessionConfigurationWithIdentifier:)])
                {
                    // Device runs on iOS 7 or OS X 10.9
                    backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfiguration:[NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, _appBundleId]];
                }
                else
#endif
                {
                    // Device runs on iOS 8+ or OS X 10.10+ or min SDK is iOS 8+ or OS X 10.10+
                    backgroundConfiguration = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier: [NSString stringWithFormat:kTSKBackgroundSessionIdentifierFormat, _appBundleId]];
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
                // We have to use a delegate as background sessions can't use completion handlers
                _backgroundSession = [NSURLSession sessionWithConfiguration:backgroundConfiguration
                                                                   delegate:self
                                                              delegateQueue:nil];
            });
        }
    }
    return self;
}


- (void) pinValidationFailedForHostname:(NSString *) serverHostname
                                   port:(NSNumber *) serverPort
                       certificateChain:(NSArray *) certificateChain
                          notedHostname:(NSString *) notedHostname
                             reportURIs:(NSArray<NSURL *> *) reportURIs
                      includeSubdomains:(BOOL) includeSubdomains
                         enforcePinning:(BOOL) enforcePinning
                              knownPins:(NSSet<NSData *> *) knownPins
                       validationResult:(TSKPinValidationResult) validationResult
{
    // Default port to 0 if not specified
    if (serverPort == nil)
    {
        serverPort = [NSNumber numberWithInt:0];
    }
    
    if (reportURIs == nil)
    {
        [NSException raise:@"TSKBackgroundReporter configuration invalid"
                    format:@"Reporter was given an invalid value for reportURIs: %@ for domain %@",
         reportURIs, notedHostname];
    }
    
    // Create the pin validation failure report
    NSArray *formattedPins = convertPinsToHpkpPins(knownPins);
    TSKPinFailureReport *report = [[TSKPinFailureReport alloc]initWithAppBundleId:_appBundleId
                                                                       appVersion:_appVersion
                                                                      appPlatform:_appPlatform
                                                                      appVendorId:_appVendorId
                                                                  trustkitVersion:TrustKitVersion
                                                                         hostname:serverHostname
                                                                             port:serverPort
                                                                         dateTime:[NSDate date] // Use the current time
                                                                    notedHostname:notedHostname
                                                                includeSubdomains:includeSubdomains
                                                                   enforcePinning:enforcePinning
                                                        validatedCertificateChain:certificateChain
                                                                        knownPins:formattedPins
                                                                 validationResult:validationResult];
    
    // Should we rate-limit this report?
    if (_shouldRateLimitReports && [TSKReportsRateLimiter shouldRateLimitReport:report])
    {
        // We recently sent the exact same report; do not send this report
        TSKLog(@"Pin failure report for %@ was not sent due to rate-limiting", serverHostname);
        return;
    }
    
    // Create a temporary file for storing the JSON data in ~/tmp
    NSURL *tmpDirURL = [NSURL fileURLWithPath:NSTemporaryDirectory() isDirectory:YES];
    NSURL *tmpFileURL = [[tmpDirURL URLByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]] URLByAppendingPathExtension:@"tsk-report"];
    
    // Write the JSON report data to the temporary file
    NSError *error;
    NSUInteger writeOptions = NSDataWritingAtomic;
#if TARGET_OS_IPHONE
    // Ensure the report is accessible when locked on iOS, in case the App has the NSFileProtectionComplete entitlement
    writeOptions = writeOptions | NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication;
#endif
    
    if (!([[report json] writeToURL:tmpFileURL options:writeOptions error:&error]))
    {
#if DEBUG
        // Only raise this exception for debug as not being able to save the report would crash a prod App
        // https://github.com/datatheorem/TrustKit/issues/32
        // This might happen when the device's storage is full?
        [NSException raise:@"TSKBackgroundReporter runtime error"
                    format:@"Report cannot be saved to file: %@", [error description]];
#endif
    }
    TSKLog(@"Report for %@ created at: %@", serverHostname, [tmpFileURL path]);
    
    
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
        TSKLog(@"Background upload - task completed successfully: pinning failure report sent");
    }
    else
    {
        TSKLog(@"Background upload - task completed with error: %@ (code %ld)", [error localizedDescription], (long)error.code);
    }
}


@end

