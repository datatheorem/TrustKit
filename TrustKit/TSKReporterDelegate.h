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
 * Initialize the reporter with the app's bundle id, app version, and the URL to send the reports to
 */
- (instancetype)initWithAppBundleId:(NSString *) appBundleId
                         appVersion:(NSString *) appVersion
                       reportingURL:(NSString *) reportingURL;

@optional

/*
 * Pin validation failed for a connection to a pinned domain
 */
- (void) pinValidationFailed:(NSString *) pinnedDomain
              serverHostname:(NSString *) hostname
                  serverPort:(NSString *) port
           includeSubdomains:(Boolean) includeSubdomains
            certificateChain:(NSArray *) validatedCertificateChain
                expectedPins:(NSArray *) knownPins;

/*
 * Pin validation succeeded for a connection to a pinned domain
 */
- (void) pinValidationSucceeded:(NSString*) pinnedDomain;

@end
