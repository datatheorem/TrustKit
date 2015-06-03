/*
 
 main.m
 TrustKitDemo
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

/* 
 This is a demo app whereby we demonstrate how to configure the TrustKit with a pin to
 www.datatheorem.com, but with the wrong pin hash value, so that we intentionally would fail https connection
 to www.datatheorem.com if the user were to input "https://www.datatheorem.com" in the textfield
 Connections to all other websites should succeed.
 */
 
#import <UIKit/UIKit.h>
#import "AppDelegate.h"

int main(int argc, char * argv[]) {
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
