//
//  TrustKit+Private.h
//  TrustKit
//
//  Created by Eric on 30/03/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#ifndef TrustKit_TrustKit_Private____FILEEXTENSION___
#define TrustKit_TrustKit_Private____FILEEXTENSION___

#import "TrustKit.h"

NSDictionary *parseTrustKitArguments(NSDictionary *TrustKitArguments);

void TSKLog(NSString *format, ...);


@interface TrustKit(Private)

+ (void) resetConfiguration;
+ (NSDictionary *) trustKitConfiguration;
+ (BOOL) wasTrustKitCalled;

@end


#endif
