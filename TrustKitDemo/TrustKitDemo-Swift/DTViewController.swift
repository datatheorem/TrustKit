// DTViewController.swift
// TrustKitDemoInSwift
//
// Copyright 2017 The TrustKit Project Authors
// Licensed under the MIT license, see associated LICENSE file for terms.
// See AUTHORS file for the list of project authors.

import TrustKit
import UIKit

class DTViewController: UIViewController, URLSessionDelegate {

    @IBOutlet weak var testInvalidPinBtn: UIButton? {
        didSet { testInvalidPinBtn?.layer.cornerRadius = 4 }  // add rounded corners
    }

    @IBOutlet weak var testValidPinBtn: UIButton? {
        didSet { testValidPinBtn?.layer.cornerRadius = 4 }  // add rounded corners
    }

    @IBOutlet weak var testNotPinnedBtn: UIButton? {
        didSet { testNotPinnedBtn?.layer.cornerRadius = 4 }
    }

    @IBOutlet weak var testWebViewInvalidPinBtn: UIButton? {
        didSet { testWebViewInvalidPinBtn?.layer.cornerRadius = 4 }
    }

    @IBOutlet weak var testWebViewValidPinBtn: UIButton? {
        didSet { testWebViewValidPinBtn?.layer.cornerRadius = 4 }
    }

    @IBOutlet weak var activityIndicator: UIActivityIndicatorView!

    lazy var session: URLSession = {
        URLSession(
            configuration: URLSessionConfiguration.ephemeral,
            delegate: self,
            delegateQueue: nil
        )
    }()

    let baseURLGoogle = "https://www.google.com/"

    let baseURLDT = "https://www.datatheorem.com/"

    let baseURLYahoo = "https://www.yahoo.com/"

    // MARK: TrustKit Pinning Reference

    nonisolated func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {

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
        let task = session.dataTask(with: url) { [weak self] (_, _, error) in
            DispatchQueue.main.async {
                switch error {
                case nil:
                    self?.displayAlert(withTitle: "Connected", message: "Connected to \(url.absoluteString)")
                case let error as URLError where error.code == .cancelled:
                    self?
                        .displayAlert(
                            withTitle: "Blocked",
                            message: "TrustKit blocked the connection to \(url.absoluteString)"
                        )
                case let error?:
                    self?
                        .displayAlert(
                            withTitle: "Failed",
                            message: "Connection to \(url.absoluteString) failed\n\n\(error)"
                        )
                }
            }
        }

        task.resume()
    }

    @IBAction func testInvalidPinning(_ sender: UIButton) {
        self.loadURL(url: URL(string: baseURLGoogle)!)
    }

    @IBAction func testValidPinning(_ sender: UIButton) {
        self.loadURL(url: URL(string: baseURLDT)!)
    }

    @IBAction func testNotPinned(_ sender: UIButton) {
        self.loadURL(url: URL(string: baseURLYahoo)!)
    }

    @IBAction func testWebViewInvalidPinning(_ sender: UIButton) {
        present(WebViewController(url: URL(string: baseURLGoogle)!), animated: true)
    }

    @IBAction func testWebViewValidPinning(_ sender: UIButton) {
        present(WebViewController(url: URL(string: baseURLDT)!), animated: true)
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
