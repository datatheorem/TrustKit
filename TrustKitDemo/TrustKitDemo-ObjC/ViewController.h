/*

 ViewController.h
 TrustKitDemo

 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController <NSURLSessionDelegate>

@property (weak, nonatomic) IBOutlet UIButton *invalidPinBtn;
@property (weak, nonatomic) IBOutlet UIButton *validPinBtn;
@property (weak, nonatomic) IBOutlet UIButton *notPinnedBtn;
@property (weak, nonatomic) IBOutlet UIButton *webViewInvalidPinBtn;
@property (weak, nonatomic) IBOutlet UIButton *webViewValidPinBtn;
@property (weak, nonatomic) IBOutlet UIActivityIndicatorView *activityIndicator;

@end
