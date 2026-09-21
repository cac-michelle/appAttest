// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "AppAttestClient",
    // App Attest 本身需要 iOS 14+，這裡要求 15+ 是為了 async/await 用起來順。
    // macOS 也列進來只是為了能在 Mac 上跑 swift test —— DeviceCheck 的實際
    // 呼叫在任何非真機環境都不會成功，那部分由 protocol 隔開。
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "AppAttestClient", targets: ["AppAttestClient"]),
    ],
    targets: [
        .target(name: "AppAttestClient"),
        .testTarget(
            name: "AppAttestClientTests",
            dependencies: ["AppAttestClient"],
            // request-hash-vectors.json 是由後端的 PHP 實作產生的。
            // 兩邊對同一份檔案做驗證，任一方改動合約都會被抓到。
            resources: [.process("Fixtures")]
        ),
    ]
)
