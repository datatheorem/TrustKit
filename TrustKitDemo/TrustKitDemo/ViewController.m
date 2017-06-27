/*
 
 ViewController.m
 TrustKitDemo
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "ViewController.h"
#import <TrustKit/TrustKit.h>

@interface ViewController ()
{
    UIActivityIndicatorView *activityIndicator;
}

@property (nonatomic, strong) NSURLSession *session;

@end

@implementation ViewController

static NSString *const baseURLYahoo = @"https://www.yahoo.com/";
static NSString *const baseURLDT = @"https://www.datatheorem.com/";

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    self.invalidPinBtn.layer.cornerRadius = 4;
    self.validPinBtn.layer.cornerRadius = 4;
    
    self.session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:self delegateQueue:nil];
    
    activityIndicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleGray];
}


- (void)loadUrlWithPinningFailure: (NSURL *)url
{
    // Load a URL with a bad pinning configuration to demonstrate a pinning failure with a report being sent
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url];
    [task resume];
    [self showActivityIndicatorInCurrentViewController];
}

- (void)loadUrl:(NSURL *)url
{
    // Show loading view
    [self showActivityIndicatorInCurrentViewController];
    
    // Load a URL with a good pinning configuration
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:url completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
        
        if (!error) {
            // Display Success Alert
            dispatch_async(dispatch_get_main_queue(), ^{
                [self displayAlertWithTitle:@"Test Result" andMessage:[NSString stringWithFormat:@"Pinning validation succeeded for %@", [url absoluteString]]];
            });
        }
        else {
            // Display Error Alert
            dispatch_async(dispatch_get_main_queue(), ^{
                [self displayAlertWithTitle:@"Test Result" andMessage:[NSString stringWithFormat:@"Pinning validation failed for [%@] : [%@]", [url absoluteString], error.description]];
            });
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

- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    // Call into TrustKit here to do pinning validation
    if (![TSKPinningValidator handleChallenge:challenge completionHandler:completionHandler])
    {
        // TrustKit did not handle this challenge: perhaps it was not for server trust
        // or the domain was not pinned. Fall back to the default behavior
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
    }
}

- (void)displayAlertWithTitle:(NSString *)title andMessage:(NSString *)message
{
    // Hide Activity Indicator
    [self hideActivityIndicator];
    
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (void)showActivityIndicatorInCurrentViewController
{
    [self.view setUserInteractionEnabled:NO];
    if (![activityIndicator isAnimating]) {
        activityIndicator.center = CGPointMake([UIScreen mainScreen].bounds.size.width/2, [UIScreen mainScreen].bounds.size.height/2 + 100);
        [self.view addSubview:activityIndicator];
        [activityIndicator startAnimating];
    }
}

- (void)hideActivityIndicator
{
    [self.view setUserInteractionEnabled:YES];
    [activityIndicator stopAnimating];
    [activityIndicator removeFromSuperview];
}

@end
