import ParabellumKit
import SwiftUI

// Parabellum design system: brand palette, Liquid Glass surfaces, aurora backdrop, brand mark.
//
// Glass: on macOS 26 (built with Xcode 26 / Swift 6.2) surfaces use Apple's native Liquid Glass
// (`glassEffect`); on macOS 14–15, or with an older toolchain, they fall back to an ultra-thin material
// with a specular rim and a soft shadow, so the app keeps the same shapes and depth everywhere.

// MARK: - Brand

enum Brand {
    /// Electric indigo: primary accent (buttons, selection, links).
    static let indigo = Color(red: 0.36, green: 0.36, blue: 1.00)
    /// Glacier cyan: second stop of the brand gradient.
    static let cyan = Color(red: 0.13, green: 0.83, blue: 0.93)
    /// Deep violet: backdrop glow.
    static let violet = Color(red: 0.55, green: 0.30, blue: 0.95)
    /// Midnight: dark backdrop base.
    static let midnight = Color(red: 0.035, green: 0.045, blue: 0.10)

    static let accent = indigo

    /// Signature gradient (brand mark, hero ring, prominent buttons).
    static let gradient = LinearGradient(
        colors: [indigo, violet, cyan],
        startPoint: .topLeading,
        endPoint: .bottomTrailing
    )

    static let motto = "Si vis pacem, para bellum"

    /// Corner radii (continuous corners everywhere).
    enum Radius {
        static let card: CGFloat = 20
        static let control: CGFloat = 12
        static let row: CGFloat = 10
    }
}

// MARK: - Glass surfaces

struct GlassSurface<S: InsettableShape>: ViewModifier {
    let shape: S
    var tint: Color?
    var interactive = false

    @ViewBuilder
    func body(content: Content) -> some View {
        #if compiler(>=6.2)
            if #available(macOS 26.0, *) {
                content.glassEffect(glass, in: shape)
            } else {
                fallback(content)
            }
        #else
            fallback(content)
        #endif
    }

    #if compiler(>=6.2)
        @available(macOS 26.0, *)
        private var glass: Glass {
            var g = Glass.regular
            if let tint {
                g = g.tint(tint.opacity(0.18))
            }
            if interactive {
                g = g.interactive()
            }
            return g
        }
    #endif

    private func fallback(_ content: Content) -> some View {
        content
            .background {
                ZStack {
                    shape.fill(.ultraThinMaterial)
                    if let tint {
                        shape.fill(tint.opacity(0.10))
                    }
                }
            }
            .overlay {
                // Specular rim: brighter on the top-left edge, like light on a glass slab.
                shape.strokeBorder(
                    LinearGradient(
                        colors: [.white.opacity(0.45), .white.opacity(0.08), .white.opacity(0.18)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 0.8
                )
            }
            .shadow(color: .black.opacity(0.18), radius: 14, x: 0, y: 6)
    }
}

extension View {
    /// Rounded glass surface (cards, panels).
    func glassSurface(cornerRadius: CGFloat = Brand.Radius.card, tint: Color? = nil) -> some View {
        modifier(GlassSurface(shape: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous), tint: tint))
    }

    /// Capsule glass (pills, chips, floating controls).
    func glassCapsule(tint: Color? = nil, interactive: Bool = false) -> some View {
        modifier(GlassSurface(shape: Capsule(style: .continuous), tint: tint, interactive: interactive))
    }

    /// Aurora backdrop behind a screen, so glass surfaces have something to refract.
    func auroraBackground() -> some View {
        background(AuroraBackground().ignoresSafeArea())
    }
}

// MARK: - Aurora backdrop

/// Soft brand glows on the window background; drifts slowly unless Reduce Motion is on.
struct AuroraBackground: View {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var drift = false

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            let h = geo.size.height
            ZStack {
                base
                glow(Brand.indigo, size: max(w, h) * 0.75)
                    .offset(x: -w * (drift ? 0.30 : 0.36), y: -h * (drift ? 0.34 : 0.28))
                glow(Brand.cyan, size: max(w, h) * 0.6)
                    .offset(x: w * (drift ? 0.36 : 0.30), y: h * (drift ? 0.30 : 0.38))
                glow(Brand.violet, size: max(w, h) * 0.5)
                    .offset(x: w * (drift ? 0.30 : 0.22), y: -h * (drift ? 0.28 : 0.36))
            }
            .frame(width: w, height: h)
            .clipped()
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 18).repeatForever(autoreverses: true)) {
                drift = true
            }
        }
    }

    private var base: some View {
        Group {
            if scheme == .dark {
                LinearGradient(
                    colors: [Brand.midnight, Color(red: 0.06, green: 0.06, blue: 0.14)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            } else {
                LinearGradient(
                    colors: [Color(red: 0.96, green: 0.96, blue: 0.99), Color(red: 0.92, green: 0.94, blue: 0.99)],
                    startPoint: .top,
                    endPoint: .bottom
                )
            }
        }
    }

    private func glow(_ color: Color, size: CGFloat) -> some View {
        Circle()
            .fill(color.opacity(scheme == .dark ? 0.32 : 0.20))
            .frame(width: size, height: size)
            .blur(radius: size * 0.28)
    }
}

// MARK: - Brand mark

/// Shield emblem with the brand gradient; `glow` adds the halo used on hero screens.
struct BrandMark: View {
    var size: CGFloat = 28
    var glow = false

    var body: some View {
        ZStack {
            if glow {
                Image(systemName: "shield.fill")
                    .font(.system(size: size, weight: .semibold))
                    .foregroundStyle(Brand.gradient)
                    .blur(radius: size * 0.35)
                    .opacity(0.7)
            }
            Image(systemName: "shield.fill")
                .font(.system(size: size, weight: .semibold))
                .foregroundStyle(Brand.gradient)
            Image(systemName: "bolt.fill")
                .font(.system(size: size * 0.42, weight: .heavy))
                .foregroundStyle(.white.opacity(0.95))
                .offset(y: -size * 0.02)
        }
        .accessibilityHidden(true)
    }
}

/// "Parabellum" wordmark with the motto underneath.
struct BrandWordmark: View {
    var showMotto = true

    var body: some View {
        HStack(spacing: 10) {
            BrandMark(size: 26)
            VStack(alignment: .leading, spacing: 1) {
                Text("Parabellum")
                    .font(.system(.title3, design: .rounded).weight(.bold))
                    .tracking(0.2)
                if showMotto {
                    Text(Brand.motto)
                        .font(.system(size: 10, weight: .medium, design: .serif))
                        .italic()
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

// MARK: - Hero status ring

/// Large protection gauge: a ring filled to `progress` in `color`, with the state symbol in its centre.
struct StatusRing: View {
    let progress: Double
    let color: Color
    let symbol: String
    var size: CGFloat = 112
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    var body: some View {
        ZStack {
            Circle()
                .fill(color.opacity(0.18))
                .blur(radius: size * 0.22)
                .scaleEffect(pulse ? 1.08 : 0.94)
            Circle()
                .stroke(color.opacity(0.16), lineWidth: size * 0.075)
            Circle()
                .trim(from: 0, to: max(0.02, min(1, progress)))
                .stroke(
                    AngularGradient(colors: [color.opacity(0.55), color, color.opacity(0.85)], center: .center),
                    style: StrokeStyle(lineWidth: size * 0.075, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
                .shadow(color: color.opacity(0.55), radius: 8)
            Image(systemName: symbol)
                .font(.system(size: size * 0.32, weight: .semibold))
                .foregroundStyle(color)
                .symbolRenderingMode(.hierarchical)
        }
        .frame(width: size, height: size)
        .animation(.smooth(duration: 0.8), value: progress)
        .onAppear {
            guard !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 2.6).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Stat tile

/// Compact metric (value + caption) on glass.
struct StatTile: View {
    let value: String
    let caption: String
    var symbol: String?
    var tint: Color = Brand.accent

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let symbol {
                Image(systemName: symbol)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(tint)
            }
            Text(value)
                .font(.system(.title2, design: .rounded).weight(.semibold))
                .monospacedDigit()
                .contentTransition(.numericText())
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .glassSurface(cornerRadius: 16)
    }
}

// MARK: - Buttons

/// Prominent brand button: gradient capsule, glass rim, press feedback.
struct BrandButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .background(Brand.gradient, in: Capsule(style: .continuous))
            .overlay(Capsule(style: .continuous).stroke(.white.opacity(0.35), lineWidth: 0.8))
            .shadow(color: Brand.indigo.opacity(isEnabled ? 0.35 : 0), radius: 10, y: 4)
            .opacity(isEnabled ? 1 : 0.45)
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .animation(.snappy(duration: 0.18), value: configuration.isPressed)
    }
}

extension ButtonStyle where Self == BrandButtonStyle {
    static var brand: BrandButtonStyle { BrandButtonStyle() }
}
