import CryptoKit
import Foundation
import MachO
import Security
#if canImport(DeviceCheck)
import DeviceCheck
#endif

public enum TGIRuntimeShield {
    private static let pinnedSPKIHashes: Set<String> = [
        "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",
        "s/tdAOmUzd8syaTuqfgGvFcn6DzA5Cmb+Vby1ST+U3Y=",
        "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
        "Vjs8r4z+80wjNcr1YKepWQboSIRi63WsWXhIMN+eWys=",
        "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TjPgfaAp63Gc=",
        "mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c=",
    ]

    private static let pinnedSuffixes: [String] = [
        "tiedemannglobe.com",
        "functionaloptimalwellness.com",
        "depositumfides.com",
        "iambetterandbetter.com",
    ]

    private static let suspiciousDylibTokens: [String] = [
        "fridagadget",
        "frida-agent",
        "mobilesubstrate",
        "substrateinserter",
        "sslkillswitch",
        "ellekit",
        "libcycript",
    ]

    private static var guardTimer: DispatchSourceTimer?

    public static func activate() {
        #if !DEBUG && !targetEnvironment(simulator) && !os(watchOS)
        denyDebuggerAttach()
        enforceIntegrityOrExit()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 5.0, repeating: 10.0)
        timer.setEventHandler {
            enforceIntegrityOrExit()
        }
        timer.resume()
        guardTimer = timer
        #endif
    }

    #if !DEBUG && !targetEnvironment(simulator) && !os(watchOS)
    private static func denyDebuggerAttach() {
        typealias PtraceFn = @convention(c) (CInt, pid_t, UnsafeMutableRawPointer?, CInt) -> CInt
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
        if let sym = dlsym(rtldDefault, "ptrace") {
            let fn = unsafeBitCast(sym, to: PtraceFn.self)
            _ = fn(31, 0, nil, 0)
        }
    }

    private static func enforceIntegrityOrExit() {
        if isProcessTraced() || hasInjectedDylib() {
            _exit(0)
        }
    }

    private static func isProcessTraced() -> Bool {
        // XNU CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1; 64-bit kinfo_proc=648B, p_flag Int32 at offset 32, P_TRACED=0x800
        var mib: [Int32] = [1, 14, 1, getpid()]
        var buf = [UInt8](repeating: 0, count: 648)
        var size = buf.count
        let rc = buf.withUnsafeMutableBytes { rawPtr -> Int32 in
            guard let base = rawPtr.baseAddress else { return -1 }
            return Darwin.sysctl(&mib, 4, base, &size, nil, 0)
        }
        if rc != 0 || size < 36 { return false }
        let flags = buf.withUnsafeBytes { rawPtr -> UInt32 in
            rawPtr.loadUnaligned(fromByteOffset: 32, as: UInt32.self)
        }
        return (flags & 0x00000800) != 0
    }

    private static func hasInjectedDylib() -> Bool {
        let count = _dyld_image_count()
        for idx in 0..<count {
            guard let cName = _dyld_get_image_name(idx) else { continue }
            let lower = String(cString: cName).lowercased()
            for token in suspiciousDylibTokens where lower.contains(token) {
                return true
            }
        }
        return false
    }
    #endif

    public static func makePinnedSession(configuration: URLSessionConfiguration = .default) -> URLSession {
        URLSession(configuration: configuration, delegate: TGIPinnedSessionDelegate.shared, delegateQueue: nil)
    }

    public static func validateServerTrust(_ serverTrust: SecTrust, host: String) -> Bool {
        let lowerHost = host.lowercased()
        let requiresPin = pinnedSuffixes.contains { lowerHost == $0 || lowerHost.hasSuffix("." + $0) }
        guard SecTrustEvaluateWithError(serverTrust, nil) else { return false }
        guard requiresPin else { return true }
        guard let cfChain = SecTrustCopyCertificateChain(serverTrust) else { return false }
        let certCount = CFArrayGetCount(cfChain)
        for idx in 0..<certCount {
            guard let rawPtr = CFArrayGetValueAtIndex(cfChain, idx) else { continue }
            let cert = unsafeBitCast(rawPtr, to: SecCertificate.self)
            guard let pubKey = SecCertificateCopyKey(cert),
                  let spkiHash = spkiSHA256Base64(for: pubKey) else { continue }
            if pinnedSPKIHashes.contains(spkiHash) {
                return true
            }
        }
        return false
    }

    private static func spkiSHA256Base64(for key: SecKey) -> String? {
        guard let rawKey = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let keyType = attrs[kSecAttrKeyType] as? String,
              let keyBits = attrs[kSecAttrKeySizeInBits] as? Int else {
            return nil
        }
        let header: [UInt8]?
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String), keyBits == 256 {
            header = [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ]
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String), keyBits == 384 {
            header = [
                0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
            ]
        } else if keyType == (kSecAttrKeyTypeRSA as String), keyBits == 2048 {
            header = [
                0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
            ]
        } else if keyType == (kSecAttrKeyTypeRSA as String), keyBits == 4096 {
            header = [
                0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
            ]
        } else {
            header = nil
        }
        guard let prefix = header else { return nil }
        var spki = Data(prefix)
        spki.append(rawKey)
        return Data(SHA256.hash(data: spki)).base64EncodedString()
    }
}

public final class TGIPinnedSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    public static let shared = TGIPinnedSessionDelegate()

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        if TGIRuntimeShield.validateServerTrust(trust, host: challenge.protectionSpace.host) {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}

public actor TGIMobileAttest {
    public static let shared = TGIMobileAttest()
    private let keyIdDefaultsKey = "com.tiedemannglobe.attest.keyId"
    private let tokenDefaultsKey = "com.tiedemannglobe.attest.sessionToken"
    private let registerEndpoint = URL(string: "https://chat.tiedemannglobe.com/api/mobile-attest/register")!

    public func signedHeaders(for body: Data) async -> [String: String] {
        let bundleId = Bundle.main.bundleIdentifier ?? "com.tiedemannglobe.unknown"
        let ts = String(Int(Date().timeIntervalSince1970))
        let bodyHex = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        var headers: [String: String] = [
            "X-TGI-Attest-Platform": "ios",
            "X-TGI-Bundle-Id": bundleId,
            "X-TGI-Attest-Timestamp": ts,
        ]
        #if canImport(DeviceCheck) && !os(watchOS)
        if #available(iOS 14.0, macOS 11.0, *), DCAppAttestService.shared.isSupported {
            do {
                let (keyId, sessionToken) = try await ensureRegisteredKey(bundleId: bundleId)
                let payload = Data("\(bundleId):\(ts):\(bodyHex)".utf8)
                let clientDataHash = Data(SHA256.hash(data: payload))
                let assertion = try await DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: clientDataHash)
                headers["X-TGI-App-Attest-Key-Id"] = keyId
                headers["X-TGI-App-Attest-Assertion"] = assertion.base64EncodedString()
                if !sessionToken.isEmpty {
                    headers["X-TGI-Attest-Token"] = sessionToken
                }
            } catch {
                // Server rejects unattested requests with HTTP 403
            }
        }
        #endif
        return headers
    }

    #if canImport(DeviceCheck) && !os(watchOS)
    @available(iOS 14.0, macOS 11.0, *)
    private func ensureRegisteredKey(bundleId: String) async throws -> (String, String) {
        let defaults = UserDefaults.standard
        if let existingKey = defaults.string(forKey: keyIdDefaultsKey),
           let existingToken = defaults.string(forKey: tokenDefaultsKey),
           !existingKey.isEmpty, !existingToken.isEmpty {
            return (existingKey, existingToken)
        }
        let keyId = try await DCAppAttestService.shared.generateKey()
        let challengeReqURL = URL(string: "https://chat.tiedemannglobe.com/api/mobile-attest/register?bundleId=\(bundleId)")!
        let session = TGIRuntimeShield.makePinnedSession()
        let (chalData, _) = try await session.data(from: challengeReqURL)
        let chalObj = (try? JSONSerialization.jsonObject(with: chalData) as? [String: Any]) ?? [:]
        let nonce = (chalObj["challenge"] as? String) ?? UUID().uuidString
        let clientHash = Data(SHA256.hash(data: Data(nonce.utf8)))
        let attestation = try await DCAppAttestService.shared.attestKey(keyId, clientDataHash: clientHash)

        var regReq = URLRequest(url: registerEndpoint)
        regReq.httpMethod = "POST"
        regReq.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let regBody: [String: String] = [
            "bundleId": bundleId,
            "keyId": keyId,
            "challenge": nonce,
            "attestation": attestation.base64EncodedString(),
        ]
        regReq.httpBody = try JSONSerialization.data(withJSONObject: regBody)
        let (regData, regResp) = try await session.data(for: regReq)
        guard let http = regResp as? HTTPURLResponse, (200..<300).contains(http.statusCode),
              let json = try? JSONSerialization.jsonObject(with: regData) as? [String: Any],
              let token = json["token"] as? String else {
            throw URLError(.userAuthenticationRequired)
        }
        defaults.set(keyId, forKey: keyIdDefaultsKey)
        defaults.set(token, forKey: tokenDefaultsKey)
        return (keyId, token)
    }
    #endif
}
