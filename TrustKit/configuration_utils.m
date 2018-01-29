/*
 
 configuration_utils.m
 TrustKit
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "configuration_utils.h"
#import "TSKTrustKitConfig.h"
#import "Dependencies/domain_registry/domain_registry.h"
#import "TSKLog.h"


static BOOL isSubdomain(NSString *domain, NSString *subdomain)
{
    // Ensure that the TLDs are the same; this can get tricky with TLDs like .co.uk so we take a cautious approach
    size_t domainRegistryLength = GetRegistryLength([domain UTF8String]);
    size_t subdomainRegistryLength = GetRegistryLength([subdomain UTF8String]);
    if (subdomainRegistryLength != domainRegistryLength)
    {
        return NO;
    }
    NSString *domainTld = [domain substringFromIndex: [domain length] - domainRegistryLength];
    NSString *subdomainTld = [subdomain substringFromIndex: [subdomain length] - subdomainRegistryLength];
    if (![domainTld isEqualToString:subdomainTld])
    {
        return NO;
    }
    
    // Retrieve the main domain without the TLD but append a . at the beginning
    // When initializing TrustKit, we check that [domain length] > domainRegistryLength
    NSString *domainLabel = [@"." stringByAppendingString:[domain substringToIndex:([domain length] - domainRegistryLength - 1)]];
    
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

NSString * _Nullable getPinningConfigurationKeyForDomain(NSString * _Nonnull hostname , NSDictionary<NSString *, TKSDomainPinningPolicy *> * _Nonnull domainPinningPolicies)
{
    NSString *notedHostname = nil;
    if (domainPinningPolicies[hostname] == nil)
    {
        // No pins explicitly configured for this domain
        // Look for an includeSubdomain pin that applies
        for (NSString *pinnedServerName in domainPinningPolicies)
        {
            // Check each domain configured with the includeSubdomain flag
            if ([domainPinningPolicies[pinnedServerName][kTSKIncludeSubdomains] boolValue])
            {
                // Is the server a subdomain of this pinned server?
                TSKLog(@"Checking includeSubdomains configuration for %@", pinnedServerName);
                if (isSubdomain(pinnedServerName, hostname))
                {
                    // Yes; let's use the parent domain's pinning configuration
                    TSKLog(@"Applying includeSubdomains configuration from %@ to %@", pinnedServerName, hostname);
                    notedHostname = pinnedServerName;
                    break;
                }
            }
        }
    }
    else
    {
        // This hostname has a pinnning configuration
        notedHostname = hostname;
    }
    
    if (notedHostname == nil)
    {
        TSKLog(@"Domain %@ is not pinned", hostname);
    }
    return notedHostname;
}
