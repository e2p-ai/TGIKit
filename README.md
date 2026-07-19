# TGIKit

Shared Swift package for TGI iOS apps (ECP, ERP, Fides, Vitae, E2P IDE).

## Modules

- `Keychain` — shared access-group bearer storage
- `MobileToken` — mobile ecp.token usability (ms exp)

## Use in an app (XcodeGen)

```yaml
packages:
  TGIKit:
    path: ../TGIKit   # or git url
targets:
  App:
    dependencies:
      - package: TGIKit
```

```swift
@_exported import TGIKit
```

## Tests

```bash
swift test
```
