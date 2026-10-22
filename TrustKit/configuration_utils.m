/*
 
 configuration_utils.m
 TrustKit
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "configuration_utils.h"
#import "public/TrustKit/TSKTrustKitConfig.h"
#import "TSKLog.h"
#include <arpa/inet.h>


static NSString * _Nullable canonicalIPAddress(NSString *hostname)
{
    // inet_pton embeds an IPv6 zone such as %en0 into the address instead of rejecting it
    if ([hostname containsString:@"%"])
    {
        return nil;
    }
    
    const int addressFamilies[] = {AF_INET, AF_INET6};
    for (size_t i = 0; i < sizeof(addressFamilies) / sizeof(addressFamilies[0]); i++)
    {
        struct in6_addr address;
        char addressString[INET6_ADDRSTRLEN];
        if (inet_pton(addressFamilies[i], [hostname UTF8String], &address) == 1)
        {
            return @(inet_ntop(addressFamilies[i], &address, addressString, sizeof(addressString)));
        }
    }
    return nil;
}

NSString *canonicalHostname(NSString *hostname)
{
    NSString *canonical = [hostname lowercaseString];
    if ([canonical hasSuffix:@"."])
    {
        canonical = [canonical substringToIndex:[canonical length] - 1];
    }
    if ([canonical hasPrefix:@"["] && [canonical hasSuffix:@"]"])
    {
        canonical = [canonical substringWithRange:NSMakeRange(1, [canonical length] - 2)];
    }
    return canonicalIPAddress(canonical) ?: canonical;
}

BOOL isIPAddress(NSString *hostname)
{
    return canonicalIPAddress(hostname) != nil;
}

BOOL isValidPinnedDomain(NSString *domain)
{
    if (isIPAddress(domain))
    {
        return YES;
    }
    
    NSCharacterSet *invalidCharacters = [[NSCharacterSet characterSetWithCharactersInString:@"abcdefghijklmnopqrstuvwxyz0123456789-_."] invertedSet];
    if ([domain rangeOfCharacterFromSet:invalidCharacters].location != NSNotFound
        || [[domain componentsSeparatedByString:@"."] containsObject:@""])
    {
        return NO;
    }
    
    // Reject a mistyped IPv4 address such as 10.0.0.256 instead of treating it as a domain name
    NSCharacterSet *nonIPv4Characters = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789."] invertedSet];
    return [domain rangeOfCharacterFromSet:nonIPv4Characters].location != NSNotFound;
}

static NSUInteger isSubdomain(NSString *domain, NSString *subdomain)
{
    return [subdomain hasSuffix:[@"." stringByAppendingString:domain]] ? [domain length] : 0;
}

NSString * _Nullable getPinningConfigurationKeyForDomain(NSString * _Nonnull serverHostname , NSDictionary<NSString *, TKSDomainPinningPolicy *> * _Nonnull domainPinningPolicies)
{
    NSString *hostname = canonicalHostname(serverHostname);
    NSString *notedHostname = nil;
    if (domainPinningPolicies[hostname] == nil)
    {
        NSUInteger bestMatch = 0;

        // No pins explicitly configured for this domain
        // Look for an includeSubdomain pin that applies
        for (NSString *pinnedServerName in domainPinningPolicies)
        {
            // Check each domain configured with the includeSubdomain flag
            if ([domainPinningPolicies[pinnedServerName][kTSKIncludeSubdomains] boolValue])
            {
                // Is the server a subdomain of this pinned server?
                os_log_debug(TSKLogHandle(), "Checking includeSubdomains configuration for %{public}@", pinnedServerName);
                NSUInteger currentMatch = isSubdomain(pinnedServerName, hostname);
                if (currentMatch > 0 && currentMatch > bestMatch)
                {
                    // Yes; let's use the parent domain's pinning configuration
                    os_log_debug(TSKLogHandle(), "Applying includeSubdomains configuration from %{public}@ to %{public}@ (new best match of %lu chars)", pinnedServerName, hostname, (unsigned long)currentMatch);
                    bestMatch = currentMatch;
                    notedHostname = pinnedServerName;
                }
                else if (currentMatch > 0)
                {
                    os_log_debug(TSKLogHandle(), "Not applying includeSubdomains configuration from %{public}@ to %{public}@ (current match of %lu chars does not exceed best match)", pinnedServerName, hostname, (unsigned long)currentMatch);
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
        os_log_debug(TSKLogHandle(), "Domain %@ is not pinned", hostname);
    }
    return notedHostname;
}

NSURLSessionConfiguration *ephemeralNSURLSessionConfiguration(void) {
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
#if TARGET_OS_IPHONE && !TARGET_OS_TV && !TARGET_OS_WATCH
    configuration.multipathServiceType = NSURLSessionMultipathServiceTypeHandover;
#endif
    return configuration;
}
