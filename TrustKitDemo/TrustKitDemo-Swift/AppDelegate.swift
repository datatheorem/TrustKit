/*
 
 AppDelegate.swift
 TrustKitDemoInSwift
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

import UIKit
import TrustKit

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        TrustKit.setLoggerBlock { (message) in
            print("TrustKit log: \(message)")
        }
        
        let trustKitConfig: [String: Any] = [
            kTSKSwizzleNetworkDelegates: false,
            kTSKPinnedDomains: [
                "yahoo.com": [
                    kTSKEnforcePinning: true,
                    kTSKIncludeSubdomains: true,
                    
                    // Invalid pins to demonstrate a pinning failure
                    kTSKPublicKeyHashes: [
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ],
                "www.datatheorem.com": [
                    kTSKEnforcePinning: true,
                    
                    // Valid pin and backup pin
                    kTSKPublicKeyHashes: [
                        "YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=",
                        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ]
            ]]
        
        TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
        
        return true
    }
}

