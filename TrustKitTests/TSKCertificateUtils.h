//
//  TSKCertificateUtils.h
//  TrustKit
//
//  Created by Alban Diquet on 5/31/15.
//  Copyright (c) 2015 Data Theorem. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TSKCertificateUtils : NSObject

+ (SecCertificateRef)createCertificateFromDer:(NSString *)derCertiticatePath;

+ (SecTrustRef)createTrustWithCertificates:(const void **)certArray
                               arrayLength:(NSInteger)certArrayLength
                        anchorCertificates:(const void **)anchorCertificates
                               arrayLength:(NSInteger)anchorArrayLength;

@end
