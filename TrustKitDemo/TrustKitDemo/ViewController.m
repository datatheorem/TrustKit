/*
 
 ViewController.m
 TrustKitDemo
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "ViewController.h"
#import <TrustKit/TrustKit.h>
#import <TrustKit/TSKPinningValidator.h>

static NSString *const baseURLYahoo = @"https://www.yahoo.com/";
static NSString *const baseURLDT = @"https://www.datatheorem.com/";

@interface ViewController ()

@property (nonatomic) NSURLSession *session;

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.invalidPinBtn.layer.cornerRadius = 4;
    self.validPinBtn.layer.cornerRadius = 4;
    
    self.session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                 delegate:self
                                            delegateQueue:NSOperationQueue.mainQueue];
}

#pragma mark TrustKit Pinning Reference

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // Call into TrustKit here to do pinning validation
    if (![TrustKit.sharedInstance.pinningValidator handleChallenge:challenge completionHandler:completionHandler])
    {
        // TrustKit did not handle this challenge: perhaps it was not for server trust
        // or the domain was not pinned. Fall back to the default behavior
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

#pragma mark Test Control

- (void)loadUrl:(NSURL *)url
{
    // Show loading view
    [self showActivityIndicatorInCurrentViewController];
    
    // Load a URL with a good pinning configuration
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        
        if (error) {
            // Display Error Alert
            [self displayAlertWithTitle:@"Test Result" messageFormat:@"Pinning validation failed for %@\n\n%@", url.absoluteString, error.description];
        }
        else {
            // Display Success Alert
            [self displayAlertWithTitle:@"Test Result" messageFormat:@"Pinning validation succeeded for %@", url.absoluteString];
        }
    }];
    [task resume];
}

- (IBAction)testInvalidPinning:(UIButton *)sender
{
    [self loadUrl:[NSURL URLWithString:baseURLYahoo]];
}

- (IBAction)testValidPinning:(UIButton *)sender
{
    [self loadUrl:[NSURL URLWithString:baseURLDT]];
}

- (void)displayAlertWithTitle:(NSString *)title messageFormat:(NSString *)format, ...
{
    // Hide Activity Indicator
    [self hideActivityIndicator];
    
    va_list args;
    va_start(args, format);
    NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:title
                                                                             message:message
                                                                      preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (void)showActivityIndicatorInCurrentViewController
{
    self.view.userInteractionEnabled = NO;
    [self.activityIndicator startAnimating];
}

- (void)hideActivityIndicator
{
    self.view.userInteractionEnabled = YES;
    [self.activityIndicator stopAnimating];
}

@end
