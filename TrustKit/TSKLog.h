/*
 
 TSKCommon.h
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

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
