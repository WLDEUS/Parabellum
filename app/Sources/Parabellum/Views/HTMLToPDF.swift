import AppKit
import WebKit

/// Paginated A4 PDF of a self-contained HTML page (the alert report): WebKit lays it out, the print
/// system cuts it into pages (`page-break-inside: avoid` on rows) and saves the job to a file.
/// No network: JavaScript off, ephemeral data store, the page itself forbids loading anything (CSP).
@MainActor
final class HTMLToPDF: NSObject, WKNavigationDelegate {
    private let webView: WKWebView
    private let window: NSWindow
    private var loaded: CheckedContinuation<Void, Error>?
    private var printed: CheckedContinuation<Bool, Never>?

    /// A4 in points.
    static let paper = NSSize(width: 595.28, height: 841.89)

    static func write(html: String, to url: URL) async throws {
        let job = HTMLToPDF()
        try await job.load(html)
        guard await job.print(to: url) else {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    private override init() {
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        config.defaultWebpagePreferences.allowsContentJavaScript = false
        let frame = NSRect(x: 0, y: 0, width: 794, height: 1123)
        webView = WKWebView(frame: frame, configuration: config)
        // Off-screen host window: the print operation needs one.
        window = NSWindow(contentRect: frame, styleMask: [.borderless], backing: .buffered, defer: false)
        super.init()
        window.isReleasedWhenClosed = false
        window.setFrameOrigin(NSPoint(x: -10_000, y: -10_000))
        window.contentView = webView
        webView.navigationDelegate = self
    }

    private func load(_ html: String) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            loaded = c
            webView.loadHTMLString(html, baseURL: nil)
        }
    }

    private func finishLoading(_ error: Error?) {
        guard let c = loaded else { return }
        loaded = nil
        if let error {
            c.resume(throwing: error)
        } else {
            c.resume()
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        finishLoading(nil)
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finishLoading(error)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finishLoading(error)
    }

    private func print(to url: URL) async -> Bool {
        let info = NSPrintInfo()
        info.paperSize = Self.paper
        info.topMargin = 36
        info.bottomMargin = 36
        info.leftMargin = 32
        info.rightMargin = 32
        info.horizontalPagination = .fit
        info.verticalPagination = .automatic
        info.isHorizontallyCentered = false
        info.isVerticallyCentered = false
        info.jobDisposition = .save
        info.dictionary()[NSPrintInfo.AttributeKey.jobSavingURL] = url
        let operation = webView.printOperation(with: info)
        operation.showsPrintPanel = false
        operation.showsProgressPanel = false
        // WebKit prints blank pages when its print view has no size.
        operation.view?.frame = webView.bounds
        return await withCheckedContinuation { (c: CheckedContinuation<Bool, Never>) in
            printed = c
            operation.runModal(
                for: window,
                delegate: self,
                didRun: #selector(printOperationDidRun(_:success:contextInfo:)),
                contextInfo: nil
            )
        }
    }

    @objc private func printOperationDidRun(_ operation: NSPrintOperation, success: Bool, contextInfo: UnsafeMutableRawPointer?) {
        printed?.resume(returning: success)
        printed = nil
        window.close()
    }
}
