// Draws Deskwarden's default app icon, used when Branding/AppIcon.icns isn't there.
//
//   swift scripts/make-app-icon.swift <output.icns>
import AppKit

let output = URL(fileURLWithPath: CommandLine.arguments[1])
let iconset = FileManager.default.temporaryDirectory.appendingPathComponent("AppIcon-\(UUID().uuidString).iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)

func render(size: Int) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0
    )!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    let side = CGFloat(size)

    // Apple's macOS icon grid: an 824 pt rounded square inside 1024.
    let inset = side * 100 / 1024
    let radius = side * 185 / 1024
    let body = NSBezierPath(roundedRect: NSRect(x: inset, y: inset, width: side - 2 * inset, height: side - 2 * inset), xRadius: radius, yRadius: radius)
    NSGradient(
        starting: NSColor(srgbRed: 0.22, green: 0.27, blue: 0.36, alpha: 1),
        ending: NSColor(srgbRed: 0.09, green: 0.11, blue: 0.16, alpha: 1)
    )!.draw(in: body, angle: -90)

    let configuration = NSImage.SymbolConfiguration(pointSize: side * 0.4, weight: .semibold)
        .applying(NSImage.SymbolConfiguration(paletteColors: [NSColor(srgbRed: 0.15, green: 0.18, blue: 0.25, alpha: 1), .white]))
    if let symbol = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(configuration) {
        let size = symbol.size
        symbol.draw(in: NSRect(x: (side - size.width) / 2, y: (side - size.height) / 2, width: size.width, height: size.height))
    }

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for (name, size) in [
    ("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128),
    ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024),
] {
    try render(size: size).write(to: iconset.appendingPathComponent("icon_\(name).png"))
}

let iconutil = Process()
iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", output.path]
try iconutil.run()
iconutil.waitUntilExit()
try? FileManager.default.removeItem(at: iconset)
exit(iconutil.terminationStatus)
