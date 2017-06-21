//
//  AppDelegate.swift
//  TrustKitDemoInSwift
//
//  Created by Nishant Paul on 20/06/17.
//  Copyright © 2017 DataTheorem. All rights reserved.
//

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
                    kTSKPublicKeyHashes: [
                         "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                         "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ],
                "www.datatheorem.com": [
                    kTSKEnforcePinning: true,
                    kTSKPublicKeyAlgorithms: [kTSKAlgorithmEcDsaSecp384r1],
                    kTSKPublicKeyHashes: [
                        "58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU=",
                        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                    ],
                    kTSKReportUris:["https://overmind.datatheorem.com/trustkit/report"],
                ]
            ]] as [String : Any]
        
        TrustKit.initialize(withConfiguration:trustKitConfig)
        
        return true
    }
}

