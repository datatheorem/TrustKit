/*
 
 parse_configuration.h
 TrustKit
 
 Copyright 2016 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#ifndef parse_configuration_h
#define parse_configuration_h

#if __has_feature(modules)
@import Foundation;
#else
#import <Foundation/Foundation.h>
#endif

NSDictionary *parseTrustKitConfiguration(NSDictionary *trustKitArguments);

#endif /* parse_configuration_h */
