//
//  TrustKit.h
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <UIKit/UIKit.h>

//! Project version number for TrustKit.
FOUNDATION_EXPORT double TrustKitVersionNumber;

//! Project version string for TrustKit.
FOUNDATION_EXPORT const unsigned char TrustKitVersionString[];

//Set up public keys of pinned certificates
@interface TKSettings : NSObject

+ (NSDictionary *)publicKeyPins;
+ (BOOL)setPublicKeyPins:(NSDictionary *)publicKeyPins shouldOverwrite:(BOOL)overwritePins;

@end