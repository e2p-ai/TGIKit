import Foundation
import TGIKit

func b64urlJSON(_ obj: [String: Any]) -> String {
    let data = try! JSONSerialization.data(withJSONObject: obj)
    return data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

var fails = 0
func check(_ c: Bool, _ n: String) {
    print((c ? "PASS " : "FAIL ") + n)
    if !c { fails += 1 }
}

let expMs = Int(Date().timeIntervalSince1970 * 1000) + 86_400_000
check(MobileToken.isUsable(b64urlJSON(["sub": "u", "exp": expMs]) + ".sig"), "unexpired usable")
let expOld = Int(Date().timeIntervalSince1970 * 1000) - 120_000
check(!MobileToken.isUsable(b64urlJSON(["sub": "u", "exp": expOld]) + ".sig"), "expired unusable")
print(fails == 0 ? "TGIKit smoke ALL PASS" : "TGIKit smoke FAILURES=\(fails)")
exit(fails == 0 ? 0 : 1)
