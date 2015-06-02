/*
 
 TrustKit+Private.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef TrustKit_TrustKit_Private____FILEEXTENSION___
#define TrustKit_TrustKit_Private____FILEEXTENSION___

#import "TrustKit.h"

NSDictionary *parseTrustKitArguments(NSDictionary *TrustKitArguments);

void TSKLog(NSString *format, ...);


@interface TrustKit(Private)

+ (void) resetConfiguration;
+ (NSDictionary *) configuration;
+ (BOOL) wasTrustKitCalled;

@end


#endif
