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


@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.destinationWebView.delegate = self;
    self.connectionTextfield.text = @"https://www.datatheorem.com/";
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

// connect to a website
- (IBAction)connectButton:(UIButton *)sender {
    if (self.connectionTextfield.hasText) {
        NSLog(@"connection field: %@", self.connectionTextfield.text);
        NSString *urlString = self.connectionTextfield.text;
        NSURL *url = [NSURL URLWithString:urlString];
        NSURLRequest *urlRequest = [NSURLRequest requestWithURL:url];
        [self.destinationWebView loadRequest:urlRequest];
    } else {
        NSLog(@"connection field is empty");
    
    }
}

// show user an error dialog when webview cannot load
- (void)webView:(UIWebView *)webView didFailLoadWithError:(NSError *)error {
    NSLog(@"%s webview fail load error=%@", __FUNCTION__, error);
    UIAlertView *infoMessage;
    infoMessage = [[UIAlertView alloc]
                   initWithTitle:@"webview load failed" message:[error localizedDescription]
                   delegate:self cancelButtonTitle:@"Cancel" otherButtonTitles:nil];
    infoMessage.alertViewStyle = UIAlertViewStyleDefault;
    [infoMessage show];
}


@end
