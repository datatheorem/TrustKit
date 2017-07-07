/*
 
 configuration_utils.h
 TrustKit
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TSKPinningValidatorCallback.h"

@import Foundation;

// Figure out if a specific domain is pinned and retrieve this domain's configuration key; returns nil if no configuration was found
NSString *getPinningConfigurationKeyForDomain(NSString *hostname, NSDictionary<NSString *, TKSDomainPinningPolicy *> *domainPinningPolicies);
