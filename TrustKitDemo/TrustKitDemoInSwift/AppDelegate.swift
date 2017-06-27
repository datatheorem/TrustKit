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

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplicationLaunchOptionsKey: Any]?) -> Bool {
        
        TrustKit.setLoggerBlock { (message) in
            print("TrustKit log: \(message)")
        }
        let trustKitConfig = [
            kTSKSwizzleNetworkDelegates: false,
            kTSKPinnedDomains: [
                "yahoo.com": [
                    kTSKEnforcePinning: true,
                    kTSKIncludeSubdomains: true,
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmRsa2048],
                    
                    // Invalid pins to demonstrate a pinning failure
                    kTSKPublicKeyHashes: [
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ],
                "www.datatheorem.com": [
                    kTSKEnforcePinning: true,
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmEcDsaSecp384r1],
                    
                    // Valid pin and backup pin
                    kTSKPublicKeyHashes: [
                        "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
                        "pL1+qb9HTMRZJmuC/bB/ZI9d302BYrrqiVuRyW+DGrU="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ]
            ]] as [String : Any]
        
        TrustKit.initialize(withConfiguration:trustKitConfig)
        
        return true
    }
}

