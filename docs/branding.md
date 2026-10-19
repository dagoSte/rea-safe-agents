# Project branding

**REA Safe Agent** is a skill that builds a safer, contained environment for
analyzing files with upstream REA. Its core purpose is to help people analyze
untrusted files with an agent through a preconfigured workflow: contain REA
and its receiving client, limit shared data, and repeat verification.

[REA — Reverse Engineer Anything](https://github.com/morluto/rea) is the
upstream analysis toolkit. REA Safe Agent supplies the skill, launcher and
verification workflow around it. The repository URL and the technical skill
identifier `rea-isolated` remain unchanged.

The [selected project logo](../skills/rea-isolated/assets/rea-safe-agent-logo.png)
is a 1536 × 1024 raster PNG with transparent background. Two connected blue
and orange modules sit above the white **REA Safe Agent** wordmark on a navy
backing. The prompt requested flat fills; the selected generated image has a
visible soft glow. Its supplied pixels and alpha were preserved unchanged.

The logo is visual branding, not a security certification or a diagram of
independent runtime layers. The two containers still share a trusted Docker
runtime and kernel environment. The README explains the actual controls and
remaining limits.

This mark was created for this project using the **built-in image generation
tool**, with a new-generation request and transparent background. No fallback
CLI or external API runner was used. It does not use the upstream REA logo or
imply upstream endorsement. The README thanks the upstream toolkit's authors,
maintainers and contributors.

## Final generation prompt

```text
Use case: logo-brand.
Create a NEW original FLAT vector-style logo for the developer project "REA Safe Agent".
Square compact composition: a simple paired-module icon above one clear wordmark.
Icon: two separate rounded geometric frames connected by a single short controlled bridge. Left frame blue/cyan with three abstract code strokes; right frame orange with a simple three-node branching diagram. Dark navy interiors. Strong clean silhouette, broad smooth strokes, balanced negative space. Keep it simple.
Wordmark exact text (case sensitive): "REA Safe Agent". One line, all words equally prominent, bold clean sans-serif. The letters MUST be solid bright WHITE (#FFFFFF), sitting on a tightly fitted solid dark NAVY (#09243A) rectangular or softly rounded backing directly below the icon. This white-on-navy wordmark is essential: do not use dark or transparent lettering. The full name must be legible at small size.
Background outside the icon and its wordmark backing MUST be genuine fully transparent alpha. Generous clear margins.
STRICT FLAT DESIGN: uniform solid color fills, crisp edges. Absolutely NO glow, NO halo, NO haze, NO light rays, NO shadow, NO gradient, NO blur, NO 3D, NO photorealism, NO texture. No extra words, no tagline, no vendor or upstream logos, no certification seal, no mockup or watermark.
```
