/*
 
 ViewController.m
 TrustKitDemo
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "ViewController.h"

@interface ViewController ()

@property (weak, nonatomic) IBOutlet UITextField *connectionTextfield;
@property (weak, nonatomic) IBOutlet UIWebView *destinationWebView;
@property NSURL *baseUrl;
@property NSURLSession *session;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.destinationWebView.delegate = self;
    
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:self
                                                     delegateQueue:nil];
    self.session = session;
    
    // First demonstrate pinning failure
    [self loadUrlWithPinningFailure];
}


- (void)loadUrlWithPinningFailure {
    // Load a URL with a bad pinning configuration to demonstrate a pinning failure with a report being sent
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:[NSURL URLWithString:@"https://www.yahoo.com/"]];
    [task resume];
}

- (void)loadUrlWithPinningSuccess {
    // Load a URL with a good pinning configuration
    self.baseUrl = [NSURL URLWithString:@"https://www.datatheorem.com/"];
    NSURLSessionDataTask *task = [self.session dataTaskWithURL:self.baseUrl];
    [task resume];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


- (void)URLSession:(NSURLSession * _Nonnull)session
              task:(NSURLSessionTask * _Nonnull)task
didCompleteWithError:(NSError * _Nullable)error
{
    if (error)
    {
        // An error will only be triggered when loading
        NSLog(@"Received error %@", error);
    
        // Now try a valid connection
        [self loadUrlWithPinningSuccess];
    }
}


- (void)URLSession:(NSURLSession * _Nonnull)session
          dataTask:(NSURLSessionDataTask * _Nonnull)dataTask
    didReceiveData:(NSData * _Nonnull)data
{
    // Display the content in the webview
    NSLog(@"Loading content");
    [self.destinationWebView loadHTMLString:[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]
                                    baseURL:self.baseUrl];
}


@end
