// Draws the Parabellum app icon as a 1024x1024 PNG: the SF Symbol `shield.lefthalf.filled` in white on a
// blue-to-teal gradient rounded square, following the macOS 11+ icon grid (824 px tile, 100 px margin).
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
NSColor(srgbRed: 0.06, green: 0.16, blue: 0.36, alpha: 1).setFill()
tile.fill()
NSGraphicsContext.restoreGraphicsState()

let topColor = NSColor(srgbRed: 0.11, green: 0.28, blue: 0.62, alpha: 1)
let bottomColor = NSColor(srgbRed: 0.02, green: 0.52, blue: 0.56, alpha: 1)
guard let gradient = NSGradient(starting: topColor, ending: bottomColor) else { fail("cannot create the gradient") }
// -90 degrees: starting color at the top, ending color at the bottom.
gradient.draw(in: tile, angle: -90)

NSColor.white.withAlphaComponent(0.10).setStroke()
tile.lineWidth = 6
tile.stroke()

// Shield glyph.
let symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 520, weight: .semibold)
guard
    let baseSymbol = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Parabellum"),
    let symbol = baseSymbol.withSymbolConfiguration(symbolConfiguration)
else { fail("SF Symbol shield.lefthalf.filled is unavailable") }

let symbolSize = symbol.size
guard symbolSize.width > 0, symbolSize.height > 0 else { fail("empty SF Symbol") }

// Symbols are template images: draw the glyph, then paint white over its opaque pixels only.
let whiteSymbol = NSImage(size: symbolSize, flipped: false) { rect in
    symbol.draw(in: rect)
    NSColor.white.set()
    rect.fill(using: .sourceAtop)
    return true
}

let maxWidth: CGFloat = 540
let maxHeight: CGFloat = 580
let scale = min(maxWidth / symbolSize.width, maxHeight / symbolSize.height)
let drawSize = NSSize(width: symbolSize.width * scale, height: symbolSize.height * scale)
let drawRect = NSRect(
    x: (sideF - drawSize.width) / 2,
    y: (sideF - drawSize.height) / 2,
    width: drawSize.width,
    height: drawSize.height
)

NSGraphicsContext.saveGraphicsState()
let glyphShadow = NSShadow()
glyphShadow.shadowColor = NSColor.black.withAlphaComponent(0.25)
glyphShadow.shadowBlurRadius = 18
glyphShadow.shadowOffset = NSSize(width: 0, height: -8)
glyphShadow.set()
whiteSymbol.draw(in: drawRect, from: .zero, operation: .sourceOver, fraction: 1.0)
NSGraphicsContext.restoreGraphicsState()

context.flushGraphics()
NSGraphicsContext.restoreGraphicsState()

guard let png = rep.representation(using: .png, properties: [:]) else { fail("PNG encoding failed") }
do {
    try png.write(to: outputURL, options: .atomic)
} catch {
    fail("cannot write \(outputURL.path): \(error.localizedDescription)")
}
