//
//  configuration_utils.h
//  TrustKit
//
//  Created by Alban Diquet on 2/20/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

@import Foundation;

// Figure out if a specific domain is pinned and retrieve this domain's configuration key; returns nil if no configuration was found
NSString * _Nullable getPinningConfigurationKeyForDomain(NSString * _Nonnull hostname, NSDictionary * _Nonnull trustKitConfiguration);
