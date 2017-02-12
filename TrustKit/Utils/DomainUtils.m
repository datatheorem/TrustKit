/*
 DomainUtils.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "DomainUtils.h"
#import "../Dependencies/domain_registry/domain_registry.h"

BOOL isSubdomain(NSString *domain, NSString *subdomain)
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
