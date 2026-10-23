/*

 SubjectPublicKeyInfo.swift
 TrustKit

 Copyright 2026 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.

 */

import Foundation

@objc(TSKSubjectPublicKeyInfo)
public final class SubjectPublicKeyInfo: NSObject {
    /// Returns the DER-encoded Subject Public Key Info of a DER-encoded certificate, exactly as it
    /// is encoded in the certificate, or nil if the certificate could not be read.
    @objc public static func data(fromCertificate certificate: Data) -> Data? {
        // An Array keeps every read below bounds-checked, including in release builds
        let der = [UInt8](certificate)
        guard let subjectPublicKeyInfo = subjectPublicKeyInfoRange(in: der) else {
            return nil
        }
        return Data(der[subjectPublicKeyInfo])
    }
}

private struct DERElement {
    let tag: UInt8
    let content: Range<Int>
    let element: Range<Int>
}

private func subjectPublicKeyInfoRange(in der: [UInt8]) -> Range<Int>? {
    guard let certificate = readElement(der, in: der.indices), certificate.tag == 0x30,
          let tbsCertificate = readElement(der, in: certificate.content), tbsCertificate.tag == 0x30 else {
        return nil
    }

    // RFC 5280 4.1: an optional [0] version, then serialNumber, signature, issuer, validity and subject
    var remaining = tbsCertificate.content
    if let version = readElement(der, in: remaining), version.tag == 0xa0 {
        remaining = version.element.upperBound..<remaining.upperBound
    }
    for expectedTag: UInt8 in [0x02, 0x30, 0x30, 0x30, 0x30] {
        guard let field = readElement(der, in: remaining), field.tag == expectedTag else {
            return nil
        }
        remaining = field.element.upperBound..<remaining.upperBound
    }

    guard let subjectPublicKeyInfo = readElement(der, in: remaining), subjectPublicKeyInfo.tag == 0x30 else {
        return nil
    }
    return subjectPublicKeyInfo.element
}

private func readElement(_ der: [UInt8], in range: Range<Int>) -> DERElement? {
    guard range.count >= 2 else {
        return nil
    }
    let tag = der[range.lowerBound]
    var contentStart = range.lowerBound + 2
    var length = Int(der[range.lowerBound + 1])
    if length & 0x80 != 0 {
        // DER has no indefinite length (0x80), and no certificate needs more than 3 length bytes
        let lengthBytes = length & 0x7f
        guard (1...3).contains(lengthBytes), range.upperBound - contentStart >= lengthBytes else {
            return nil
        }
        length = der[contentStart..<contentStart + lengthBytes].reduce(0) { $0 << 8 | Int($1) }
        contentStart += lengthBytes
    }
    guard range.upperBound - contentStart >= length else {
        return nil
    }
    return DERElement(tag: tag,
                      content: contentStart..<contentStart + length,
                      element: range.lowerBound..<contentStart + length)
}
