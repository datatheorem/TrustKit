//
//  TrustKit.h
//  TrustKit
//
//  Created by Alban Diquet on 2/9/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for TrustKit.
FOUNDATION_EXPORT double TrustKitVersionNumber;

//! Project version string for TrustKit.
FOUNDATION_EXPORT const unsigned char TrustKitVersionString[];


// Keys for each domain within the config dictionnary
extern NSString * const kTSKPublicKeyHashes;
extern NSString * const kTSKEnforcePinning;
extern NSString * const kTSKIncludeSubdomains;
extern NSString * const kTSKPublicKeyAlgorithms;
extern NSString * const kTSKReportUris;

// Public key algorithms supported by TrustKit
extern NSString * const kTSKAlgorithmRsa2048;
extern NSString * const kTSKAlgorithmRsa4096;
extern NSString * const kTSKAlgorithmEcDsaSecp256r1;


@interface TrustKit : NSObject

+ (void) initializeWithConfiguration:(NSDictionary *)TrustKitConfig;

@end
