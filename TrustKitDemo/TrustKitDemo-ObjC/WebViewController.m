#import "WebViewController.h"
#import <TrustKit/TrustKit.h>
#import <WebKit/WebKit.h>

@interface WebViewController () <WKNavigationDelegate>

@property (nonatomic) NSURL *url;

@end

@implementation WebViewController

- (instancetype)initWithURL:(NSURL *)url
{
    self = [super initWithNibName:nil bundle:nil];
    if (self)
    {
        _url = url;
    }
    return self;
}

- (void)loadView
{
    WKWebView *webView = [[WKWebView alloc] init];
    webView.navigationDelegate = self;
    self.view = webView;
    [webView loadRequest:[NSURLRequest requestWithURL:self.url]];
}

- (void)webView:(WKWebView *)webView
didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
{
    void (^completeOnMainQueue)(NSURLSessionAuthChallengeDisposition, NSURLCredential *) = ^(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completionHandler(disposition, credential);
        });
    };
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        TSKPinningValidator *pinningValidator = [[TrustKit sharedInstance] pinningValidator];
        if (![pinningValidator handleChallenge:challenge completionHandler:completeOnMainQueue])
        {
            completeOnMainQueue(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        }
    });
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error
{
    UIAlertController *alertController;
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled) {
        alertController = [UIAlertController alertControllerWithTitle:@"Blocked"
                                                              message:[NSString stringWithFormat:@"TrustKit blocked the connection to %@", self.url.absoluteString]
                                                       preferredStyle:UIAlertControllerStyleAlert];
    }
    else {
        alertController = [UIAlertController alertControllerWithTitle:@"Failed"
                                                              message:[NSString stringWithFormat:@"Loading %@ failed\n\n%@", self.url.absoluteString, error.description]
                                                       preferredStyle:UIAlertControllerStyleAlert];
    }
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

@end
