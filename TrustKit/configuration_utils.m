//
//  configuration_utils.m
//  TrustKit
//
//  Created by Alban Diquet on 2/20/17.
//  Copyright © 2017 TrustKit. All rights reserved.
//

#import "configuration_utils.h"
#import "Dependencies/domain_registry/domain_registry.h"
#import "TrustKit+Private.h"


static BOOL isSubdomain(NSString *domain, NSString *subdomain)
{
    size_t domainRegistryLength = GetRegistryLength([domain UTF8String]);
    if (GetRegistryLength([subdomain UTF8String]) != domainRegistryLength)
    {
        // Different TLDs
        return NO;
    }
    
    // Retrieve the main domain without the TLD
    // When initializing TrustKit, we check that [domain length] > domainRegistryLength
    NSString *domainLabel = [domain substringToIndex:([domain length] - domainRegistryLength - 1)];
    
    // Retrieve the subdomain's domain without the TLD
    NSString *subdomainLabel = [subdomain substringToIndex:([subdomain length] - domainRegistryLength - 1)];
    
    // Does the subdomain contain the domain
    NSArray *subComponents = [subdomainLabel componentsSeparatedByString:domainLabel];
    if ([[subComponents lastObject] isEqualToString:@""])
    {
        // This is a subdomain
        return YES;
    }
    return NO;
}


NSString *getPinningConfigurationKeyForDomain(NSString *hostname, NSDictionary *trustKitConfiguration)
{
    NSString *configHostname = nil;
    NSDictionary *domainsPinningPolicy = trustKitConfiguration[kTSKPinnedDomains];
    
    if (domainsPinningPolicy[hostname] == nil)
    {
        // No pins explicitly configured for this domain
        // Look for an includeSubdomain pin that applies
        for (NSString *pinnedServerName in domainsPinningPolicy)
        {
            // Check each domain configured with the includeSubdomain flag
            if ([domainsPinningPolicy[pinnedServerName][kTSKIncludeSubdomains] boolValue])
            {
                // Is the server a subdomain of this pinned server?
                TSKLog(@"Checking includeSubdomains configuration for %@", pinnedServerName);
                if (isSubdomain(pinnedServerName, hostname))
                {
                    // Yes; let's use the parent domain's pinning configuration
                    TSKLog(@"Applying includeSubdomains configuration from %@ to %@", pinnedServerName, hostname);
                    configHostname = pinnedServerName;
                    break;
                }
            }
        }
    }
    else
    {
        // This hostname has a pinnning configuration
        configHostname = hostname;
    }
    
    if (configHostname == nil)
    {
        TSKLog(@"Domain %@ is not pinned", hostname);
    }
    return configHostname;
}
