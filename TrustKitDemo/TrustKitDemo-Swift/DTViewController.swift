/*
 
 DTViewController.swift
 TrustKitDemoInSwift
 
 Copyright 2017 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

import UIKit
import TrustKit

class DTViewController: UIViewController, URLSessionDelegate {

    @IBOutlet weak var testInvalidPinBtn: UIButton? {
        didSet { testValidPinBtn?.layer.cornerRadius = 4; } // add rounded corners
    }
    
    @IBOutlet weak var testValidPinBtn: UIButton? {
        didSet { testValidPinBtn?.layer.cornerRadius = 4; }  // add rounded corners
    }
    
    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!
    
    lazy var session: URLSession = {
        URLSession(configuration: URLSessionConfiguration.ephemeral,
                                         delegate: self,
                                         delegateQueue: OperationQueue.main)
    }()
    
    let baseURLYahoo = "https://www.yahoo.com/"
    
    let baseURLDT = "https://www.datatheorem.com/"
    
    // MARK: TrustKit Pinning Reference
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        // Call into TrustKit here to do pinning validation
        if TrustKit.sharedInstance().pinningValidator.handle(challenge, completionHandler: completionHandler) == false {
            // TrustKit did not handle this challenge: perhaps it was not for server trust
            // or the domain was not pinned. Fall back to the default behavior
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    // MARK: Test Control
    
    func loadURL(url: URL) {
        // Show loading view
        showActivityIndicatorInCurrentViewController()
        
        // Load a URL with a good pinning configuration
        let task = session.dataTask(with: url) { [weak self] (data, response, error) in
            guard error == nil else {
                // Display Error Alert
                self?.displayAlert(withTitle: "Test Result",
                                   message: "Pinning validation failed for \(url.absoluteString)\n\n\(error.debugDescription)")
                return
            }
            
            // Display Success Alert
            self?.displayAlert(withTitle: "Test Result",
                               message: "Pinning validation succeeded for \(url.absoluteString)")
        }
        
        task.resume()
    }
    
    @IBAction func testInvalidPinning(_ sender: UIButton) {
        self.loadURL(url: URL(string: baseURLYahoo)!)
    }
    
    @IBAction func testValidPinning(_ sender: UIButton) {
        self.loadURL(url: URL(string: baseURLDT)!)
    }
    
    func displayAlert(withTitle title: String, message: String) {
        // Hide Activity Indicator
        hideActivityIndicator()
        
        let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert)
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        present(alertController, animated: true, completion: nil)
    }
    
    func showActivityIndicatorInCurrentViewController() {
        view.isUserInteractionEnabled = false
        activityIndicator.startAnimating()
    }
    
    func hideActivityIndicator() {
        view.isUserInteractionEnabled = true
        activityIndicator.stopAnimating()
    }
}

