// Draws the Parabellum app icon as a 1024x1024 PNG, following the macOS 11+ icon grid (824 px tile,
// 100 px margin): a midnight tile lit by indigo / violet / cyan aurora glows, a glass shield in the brand
// gradient with a specular highlight, and a white bolt.
//
// Usage: swift installer/app/make-icon.swift <out.png>
//
// Run by scripts/build-app.sh, which turns the PNG into AppIcon.icns with sips + iconutil.
// Any failure here is non-fatal for the build (the app then ships with the generic icon).

import AppKit

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("make-icon: \(message)\n".utf8))
    exit(1)
}

let arguments = CommandLine.arguments
guard arguments.count == 2 else { fail("usage: make-icon.swift <out.png>") }
let outputURL = URL(fileURLWithPath: arguments[1])

let side = 1024
let sideF = CGFloat(side)

guard let rep = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: side,
    pixelsHigh: side,
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
) else { fail("cannot allocate the bitmap") }
rep.size = NSSize(width: sideF, height: sideF)

guard let context = NSGraphicsContext(bitmapImageRep: rep) else { fail("cannot create a graphics context") }
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.imageInterpolation = .high

// Rounded tile with a soft drop shadow.
let tileRect = NSRect(x: 100, y: 100, width: 824, height: 824)
let tile = NSBezierPath(roundedRect: tileRect, xRadius: 185, yRadius: 185)

NSGraphicsContext.saveGraphicsState()
let tileShadow = NSShadow()
tileShadow.shadowColor = NSColor.black.withAlphaComponent(0.30)
tileShadow.shadowBlurRadius = 28
tileShadow.shadowOffset = NSSize(width: 0, height: -12)
tileShadow.set()
NSColor(srgbRed: 0.035, green: 0.045, blue: 0.10, alpha: 1).setFill()
tile.fill()
NSGraphicsContext.restoreGraphicsState()

let midnight = NSColor(srgbRed: 0.035, green: 0.045, blue: 0.10, alpha: 1)
let indigo = NSColor(srgbRed: 0.36, green: 0.36, blue: 1.00, alpha: 1)
let violet = NSColor(srgbRed: 0.55, green: 0.30, blue: 0.95, alpha: 1)
let cyan = NSColor(srgbRed: 0.13, green: 0.83, blue: 0.93, alpha: 1)

// Aurora glows, clipped to the tile.
NSGraphicsContext.saveGraphicsState()
tile.addClip()
midnight.setFill()
tile.fill()
func glow(_ color: NSColor, center: NSPoint, radius: CGFloat, alpha: CGFloat) {
    guard let g = NSGradient(colors: [color.withAlphaComponent(alpha), color.withAlphaComponent(0)]) else { return }
    g.draw(fromCenter: center, radius: 0, toCenter: center, radius: radius, options: [])
}
glow(indigo, center: NSPoint(x: 260, y: 820), radius: 620, alpha: 0.85)
glow(violet, center: NSPoint(x: 820, y: 760), radius: 480, alpha: 0.55)
glow(cyan, center: NSPoint(x: 760, y: 200), radius: 560, alpha: 0.70)
NSGraphicsContext.restoreGraphicsState()

NSColor.white.withAlphaComponent(0.16).setStroke()
tile.lineWidth = 5
tile.stroke()

// Glass shield: brand gradient inside the glyph, specular sheen on its upper half.
func glyph(_ name: String, pointSize: CGFloat, weight: NSFont.Weight) -> NSImage {
    let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: weight)
    guard let base = NSImage(systemSymbolName: name, accessibilityDescription: "Parabellum"),
          let image = base.withSymbolConfiguration(config), image.size.width > 0
    else { fail("SF Symbol \(name) is unavailable") }
    return image
}

func fitted(_ size: NSSize, maxWidth: CGFloat, maxHeight: CGFloat, centerY: CGFloat) -> NSRect {
    let scale = min(maxWidth / size.width, maxHeight / size.height)
    let w = size.width * scale
    let h = size.height * scale
    return NSRect(x: (sideF - w) / 2, y: centerY - h / 2, width: w, height: h)
}

let shield = glyph("shield.fill", pointSize: 520, weight: .semibold)
let shieldRect = fitted(shield.size, maxWidth: 520, maxHeight: 590, centerY: sideF / 2)
let glassShield = NSImage(size: shield.size, flipped: false) { rect in
    shield.draw(in: rect)
    if let g = NSGradient(colors: [indigo, violet, cyan]) {
        NSGraphicsContext.current?.compositingOperation = .sourceAtop
        g.draw(in: rect, angle: -55)
    }
    // Sheen: white fading down over the top half.
    if let sheen = NSGradient(colors: [NSColor.white.withAlphaComponent(0.42), NSColor.white.withAlphaComponent(0)]) {
        NSGraphicsContext.current?.compositingOperation = .sourceAtop
        sheen.draw(in: NSRect(x: rect.minX, y: rect.midY, width: rect.width, height: rect.height / 2), angle: -90)
    }
    return true
}

NSGraphicsContext.saveGraphicsState()
let shieldGlow = NSShadow()
shieldGlow.shadowColor = indigo.withAlphaComponent(0.75)
shieldGlow.shadowBlurRadius = 60
shieldGlow.shadowOffset = NSSize(width: 0, height: -10)
shieldGlow.set()
glassShield.draw(in: shieldRect, from: .zero, operation: .sourceOver, fraction: 1.0)
NSGraphicsContext.restoreGraphicsState()

let bolt = glyph("bolt.fill", pointSize: 260, weight: .heavy)
let boltRect = fitted(bolt.size, maxWidth: 200, maxHeight: 250, centerY: sideF / 2 + 10)
let whiteBolt = NSImage(size: bolt.size, flipped: false) { rect in
    bolt.draw(in: rect)
    NSColor.white.set()
    rect.fill(using: .sourceAtop)
    return true
}
NSGraphicsContext.saveGraphicsState()
let boltShadow = NSShadow()
boltShadow.shadowColor = NSColor.black.withAlphaComponent(0.30)
boltShadow.shadowBlurRadius = 16
boltShadow.shadowOffset = NSSize(width: 0, height: -6)
boltShadow.set()
whiteBolt.draw(in: boltRect, from: .zero, operation: .sourceOver, fraction: 1.0)
NSGraphicsContext.restoreGraphicsState()

context.flushGraphics()
NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else { fail("PNG encoding failed") }
do {
    try png.write(to: outputURL, options: .atomic)
} catch {
    fail("cannot write \(outputURL.path): \(error.localizedDescription)")
}
