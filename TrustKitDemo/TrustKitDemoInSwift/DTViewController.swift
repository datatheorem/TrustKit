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

    @IBOutlet weak var testInvalidPinBtn: UIButton!
    @IBOutlet weak var testValidPinBtn: UIButton!
    var session: URLSession!
    var activityIndicator: UIActivityIndicatorView!
    let baseURLYahoo = "https://www.yahoo.com/"
    let baseURLDT = "https://www.datatheorem.com/"
    
    override func viewDidLoad()
    {
        super.viewDidLoad()
        
        // Customize look and feel of buttons
        self.testInvalidPinBtn.layer.cornerRadius = 4;
        self.testValidPinBtn.layer.cornerRadius = 4;
        
        // Create URLSession object
        self.session = URLSession(configuration: URLSessionConfiguration.ephemeral, delegate: self, delegateQueue: nil)
        
        // Create loader view
        self.activityIndicator = UIActivityIndicatorView(activityIndicatorStyle: .gray)
    }

    func loadURL(url: URL)
    {
        // Show loading view
        self.showActivityIndicatorInCurrentViewController()
        
        // Load a URL with a good pinning configuration
        let task = self.session.dataTask(with: url) { (data, response, error) in
            if error == nil {
                // Display Success Alert
                DispatchQueue.main.async {
                    self.displayAlert(withTitle: "Test Result", messsage: "Pinning validation succeeded for \(url.absoluteString)")
                }
            }
            else {
                // Display Error Alert
                DispatchQueue.main.async {
                    self.displayAlert(withTitle: "Test Result", messsage: "Pinning validation failed for [\(url.absoluteString)] : [\(error.debugDescription)]")
                }
            }
        }
        task.resume()
    }
    
    @IBAction func testInvalidPinning(_ sender: UIButton)
    {
        self.loadURL(url: URL(string: baseURLYahoo)!)
    }
    
    @IBAction func testValidPinning(_ sender: UIButton)
    {
        self.loadURL(url: URL(string: baseURLDT)!)
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void)
    {
        // Call into TrustKit here to do pinning validation
        if TrustKit.sharedInstance().pinningValidator.handle(challenge, completionHandler: completionHandler) == false {
            // TrustKit did not handle this challenge: perhaps it was not for server trust
            // or the domain was not pinned. Fall back to the default behavior
            completionHandler(.performDefaultHandling, nil)
        }
    }
    
    func displayAlert(withTitle title: String, messsage: String)
    {
        // Hide Activity Indicator
        self.hideActivityIndicator()
        
        let alertController = UIAlertController(title: title, message: messsage, preferredStyle: .alert)
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        self.present(alertController, animated: true, completion: nil)
    }
    
    func showActivityIndicatorInCurrentViewController()
    {
        self.view.isUserInteractionEnabled = false
        self.activityIndicator.center = CGPoint(x: UIScreen.main.bounds.size.width/2, y: UIScreen.main.bounds.size.height/2 + 100)
        self.view.addSubview(self.activityIndicator)
        self.activityIndicator.startAnimating()
    }
    
    func hideActivityIndicator()
    {
        self.view.isUserInteractionEnabled = true
        self.activityIndicator.stopAnimating()
        self.activityIndicator.removeFromSuperview()
    }
}

