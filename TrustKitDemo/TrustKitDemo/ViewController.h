//
//  ViewController.h
//  TrustKitDemo
//
//  Created by Nishant Paul on 19/06/17.
//  Copyright © 2017 DataTheorem. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface ViewController : UIViewController <NSURLSessionDelegate>

@property (weak, nonatomic) IBOutlet UIButton *invalidPinBtn;
@property (weak, nonatomic) IBOutlet UIButton *validPinBtn;

@end

