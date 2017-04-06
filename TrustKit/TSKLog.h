//
//  TSKCommon.h
//  TrustKit
//
//  Created by Adam Kaplan on 4/6/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

// Common header with internal constants and defines.

#ifndef TSKCommon_h
#define TSKCommon_h

// The logging function we use within TrustKit
#ifdef DEBUG
#define TSKLog(format, ...) NSLog(@"=== TrustKit: " format, ##__VA_ARGS__);
#else
#define TSKLog(format, ...)
#endif

#endif /* TSKCommon_h */
