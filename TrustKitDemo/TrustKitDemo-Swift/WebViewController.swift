import UIKit
import WebKit
import TrustKit

class WebViewController: UIViewController, WKNavigationDelegate {

    let url: URL
    private var blockedHost: String?

    init(url: URL) {
        self.url = url
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func loadView() {
        let webView = WKWebView()
        webView.navigationDelegate = self
        view = webView
        webView.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView,
                 didReceive challenge: URLAuthenticationChallenge,
                 completionHandler: @escaping @MainActor @Sendable (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let host = challenge.protectionSpace.host
        DispatchQueue.global(qos: .userInitiated).async {
            let completeOnMainQueue = { (disposition: URLSession.AuthChallengeDisposition, credential: URLCredential?) in
                DispatchQueue.main.async {
                    if disposition == .cancelAuthenticationChallenge {
                        self.blockedHost = host
                    }
                    completionHandler(disposition, credential)
                }
            }
            if !TrustKit.sharedInstance().pinningValidator.handle(challenge, completionHandler: completeOnMainQueue) {
                completeOnMainQueue(.performDefaultHandling, nil)
            }
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        let failingURL = (error as NSError).userInfo[NSURLErrorFailingURLErrorKey] as? URL ?? webView.url
        let failingAddress = failingURL?.absoluteString ?? url.absoluteString
        let alertController: UIAlertController
        if let blockedHost, failingURL?.host == blockedHost {
            alertController = UIAlertController(title: "Blocked", message: "TrustKit blocked the connection to \(failingAddress)", preferredStyle: .alert)
        } else if let error = error as? URLError, error.code == .cancelled {
            return
        } else {
            alertController = UIAlertController(title: "Failed", message: "Loading \(failingAddress) failed\n\n\(error)", preferredStyle: .alert)
        }
        alertController.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        present(alertController, animated: true, completion: nil)
    }
}
