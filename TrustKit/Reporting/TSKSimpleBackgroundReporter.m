//
//  TSKSimpleBackgroundReporter.m
//  TrustKit
//
//  Created by Angela Chow on 5/14/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import "TSKSimpleBackgroundReporter.h"

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
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    //make a file name to write the data to using the documents directory:
    NSString *tmpFilePath = [NSString stringWithFormat:@"%@/TSKReport.tmp", documentsDirectory];
    
    //Write postdata to file as we can only use background upload task with file
    if (!([postData writeToFile:tmpFilePath atomically:YES])) {
        [NSException raise:@"TrustKit Simple Reporter runtime error"
                    format:@"Report cannot be saved to file"];
    }
    
    
    NSURLSessionUploadTask *postDataTask =
    [[self backgroundSession] uploadTaskWithRequest: request
                                           fromFile: [NSURL URLWithString:[NSString stringWithFormat:@"file://%@", tmpFilePath]]];
    
    
    [postDataTask resume];
    
    
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


@end

