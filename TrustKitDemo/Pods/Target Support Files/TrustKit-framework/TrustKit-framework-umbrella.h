#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

#import "TrustKit.h"
#import "TSKTrustKitConfig.h"
#import "TSKPinningValidator.h"
#import "TSKPinningValidatorCallback.h"
#import "TSKPinningValidatorResult.h"
#import "TSKTrustDecision.h"

FOUNDATION_EXPORT double TrustKitVersionNumber;
FOUNDATION_EXPORT const unsigned char TrustKitVersionString[];

