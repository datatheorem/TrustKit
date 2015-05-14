//
//  TSKReporterDelegate.h
//  TrustKit
//
//  Created by Angela Chow on 4/23/15.
//  Copyright (c) 2015 Yahoo! Inc. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol TSKReporterDelegate <NSObject>
/*
 * Initialize the reporter with the app's bundle id, and app version
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion;


/*
 * Pin validation failed for a connection to a pinned domain
 */
- (void) pinValidationFailed:(NSString *) pinnedDomainStr
              serverHostname:(NSString *) hostnameStr
                  serverPort:(NSNumber *) port
                reportingURL:(NSString *) reportingURLStr
           includeSubdomains:(Boolean) includeSubdomains
            certificateChain:(NSArray *) validatedCertificateChain
                expectedPins:(NSArray *) knownPins;

@optional

/*
 * Pin validation succeeded for a connection to a pinned domain.
 *
 * This is an optional function, as usually, reports are only sent upon pin failure.  However, a
 * smart reporter would realize that sending reports while connections are being MITM is not the
 * best way of ensuring reports are being successfully received.  Therefore, those reporters
 * may delay the sending of those reports and preferably send them when the connections
 * are no longer in the MITM state.  In order to know that connections are no longer MITM, 
 * the pinValidationSucceeded function will provide a way to know that connections are fine now.
 */
- (void) pinValidationSucceeded:(NSString*) pinnedDomain;

@end
