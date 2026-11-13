"""Generates Leviathan's engraved-plate artwork (light + dark). Style: 1651 copperplate frontispiece."""
import math, os, random, sys
out = sys.argv[1]; os.makedirs(out, exist_ok=True)
FONT = "'Iowan Old Style','Palatino Linotype',Palatino,'Book Antiqua',Georgia,serif"
THEMES = {"light": ("#efe6d2", "#1d1a16", "#8a2a1b"), "dark": ("#0e0d0b", "#d8ccb0", "#c0583f")}

def banner(theme):
    paper, ink, red = THEMES[theme]
    W, H = 1280, 480
    random.seed(7)
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="Leviathan">',
         f'<rect width="{W}" height="{H}" fill="{paper}"/>']
    # plate frame: double rule with corner ticks
    o.append(f'<rect x="18" y="18" width="{W-36}" height="{H-36}" fill="none" stroke="{ink}" stroke-width="2.2"/>')
    o.append(f'<rect x="27" y="27" width="{W-54}" height="{H-54}" fill="none" stroke="{ink}" stroke-width="0.7"/>')
    for x, y in ((27, 27), (W-27, 27), (27, H-27), (W-27, H-27)):
        o.append(f'<circle cx="{x}" cy="{y}" r="3.2" fill="{paper}" stroke="{ink}" stroke-width="0.8"/>')
    # sea: engraved hatching, denser toward the bottom
    sea_top = 330
    for i in range(21):
        y = sea_top + i * 4.6
        amp = 2.2 + i * 0.12; ph = random.random() * 6.28; k = 0.018 + random.random() * 0.01
        pts = " ".join(f"{x},{y + amp*math.sin(k*x+ph):.1f}" for x in range(30, W-29, 8))
        o.append(f'<polyline points="{pts}" fill="none" stroke="{ink}" stroke-width="{0.5+i*0.035:.2f}" opacity="{0.55+i*0.015:.2f}"/>')
    # serpent: three coils rising from the water, body built from hundreds of small scales
    def spine(t):  # t in [0,1]
        x = 130 + t * 960
        y = sea_top + 26 - 150 * abs(math.sin(t * math.pi * 2.5)) * (0.78 + 0.22 * t)
        return x, y
    N = 900
    pts = [spine(i / N) for i in range(N + 1)]
    def thick(t): return 30 * (1 - 0.35 * t)
    # outline of body above the waterline
    for side in (1, -1):
        seg = []
        for i in range(N + 1):
            t = i / N; x, y = pts[i]
            x2, y2 = pts[min(i + 1, N)] if i < N else pts[i]
            x1, y1 = pts[max(i - 1, 0)]
            dx, dy = x2 - x1, y2 - y1; L = math.hypot(dx, dy) or 1
            nx, ny = -dy / L, dx / L
            px, py = x + side * nx * thick(t) / 2, y + side * ny * thick(t) / 2
            if py < sea_top + 2:
                seg.append(f"{px:.1f},{py:.1f}")
            elif seg:
                o.append(f'<polyline points="{" ".join(seg)}" fill="none" stroke="{ink}" stroke-width="1.6"/>'); seg = []
        if seg:
            o.append(f'<polyline points="{" ".join(seg)}" fill="none" stroke="{ink}" stroke-width="1.6"/>')
    # scales: rows of small arcs along the body
    for i in range(0, N, 6):
        t = i / N; x, y = pts[i]
        x2, y2 = pts[i + 1]; dx, dy = x2 - x, y2 - y; L = math.hypot(dx, dy) or 1
        nx, ny = -dy / L, dx / L; ang = math.degrees(math.atan2(dy, dx))
        th = thick(t)
        for row in (-0.3, 0.0, 0.3):
            off = row * th + (1.5 if (i // 6) % 2 else -1.5)
            cx, cy = x + nx * off, y + ny * off
            if cy > sea_top - 1:
                continue
            r = th * 0.16
            o.append(f'<path d="M{-r:.1f},0 A{r:.1f},{r:.1f} 0 0 0 {r:.1f},0" transform="translate({cx:.1f},{cy:.1f}) rotate({ang:.1f})" fill="none" stroke="{ink}" stroke-width="0.7"/>')
    # head at the raised right end, facing right; one red eye is the only colour on the plate
    hx, hy = pts[-1]
    g = f'<g transform="translate({hx:.1f},{hy:.1f})">'
    g += f'<path d="M-14,-12 C6,-26 34,-24 58,-12 C66,-8 70,-4 72,0 C54,4 36,6 20,8 C30,12 44,14 52,18 C34,26 8,24 -12,12 Z" fill="{paper}" stroke="{ink}" stroke-width="1.8"/>'
    g += "".join(f'<line x1="{24+k*7}" y1="{7+k*0.4:.1f}" x2="{28+k*7}" y2="{12+k*0.3:.1f}" stroke="{ink}" stroke-width="0.7"/>' for k in range(6))
    g += f'<circle cx="34" cy="-8" r="3.6" fill="{red}"/>'
    g += "".join(f'<path d="M{-14+k*9},{-12-k*1.5} L{-20+k*9},{-32+k*2} L{-6+k*9},{-15-k*1.6}" fill="{paper}" stroke="{ink}" stroke-width="1"/>' for k in range(5))
    o.append(g + "</g>")
    # spray where the coils meet the water
    for xs in (130, 514, 898):
        for _ in range(40):
            a = random.uniform(math.pi * 1.05, math.pi * 1.95); d = random.uniform(6, 36)
            o.append(f'<circle cx="{xs + d*math.cos(a)*1.4:.1f}" cy="{sea_top + d*math.sin(a)*0.6:.1f}" r="{random.uniform(0.5,1.3):.1f}" fill="{ink}"/>')
    # lettering
    o.append(f'<text x="{W/2}" y="104" text-anchor="middle" font-family="{FONT}" font-size="78" letter-spacing="22" fill="{ink}">LEVIATHAN</text>')
    o.append(f'<line x1="{W/2-300}" y1="126" x2="{W/2+300}" y2="126" stroke="{ink}" stroke-width="0.8"/>')
    o.append(f'<text x="{W/2}" y="156" text-anchor="middle" font-family="{FONT}" font-size="21" font-style="italic" fill="{ink}">stops viruses before they run on your Mac</text>')
    o.append(f'<rect x="28" y="{H-74}" width="{W-56}" height="40" fill="{paper}"/>')
    o.append(f'<text x="{W/2}" y="{H-48}" text-anchor="middle" font-family="{FONT}" font-size="13" letter-spacing="5" fill="{ink}">NON EST POTESTAS SUPER TERRAM QUAE COMPARETUR EI  ·  IOB XLI</text>')
    o.append('</svg>')
    return "\n".join(o)

def plate(theme, label, w=360, h=64, href_arrow=True):
    paper, ink, red = THEMES[theme]
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{label}">',
         f'<rect x="1" y="1" width="{w-2}" height="{h-2}" fill="{ink}" stroke="{ink}" stroke-width="2"/>',
         f'<rect x="6" y="6" width="{w-12}" height="{h-12}" fill="none" stroke="{paper}" stroke-width="0.8"/>',
         f'<text x="{w/2}" y="{h/2+7}" text-anchor="middle" font-family="{FONT}" font-size="20" letter-spacing="4" fill="{paper}">{label}</text>',
         '</svg>']
    return "\n".join(o)

def rule(theme, numeral, title, w=1280, h=56):
    paper, ink, red = THEMES[theme]
    o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{title}">',
         f'<line x1="0" y1="{h/2}" x2="{w/2-200}" y2="{h/2}" stroke="{ink}" stroke-width="0.8"/>',
         f'<line x1="{w/2+200}" y1="{h/2}" x2="{w}" y2="{h/2}" stroke="{ink}" stroke-width="0.8"/>',
         f'<text x="{w/2}" y="{h/2+8}" text-anchor="middle" font-family="{FONT}" font-size="22" letter-spacing="6" fill="{ink}"><tspan fill="{red}">{numeral}</tspan>  {title}</text>',
         '</svg>']
    return "\n".join(o)

for th in THEMES:
    open(f"{out}/banner-{th}.svg", "w").write(banner(th))
    open(f"{out}/install-{th}.svg", "w").write(plate(th, "INSTALL IN ONE LINE"))
    open(f"{out}/download-{th}.svg", "w").write(plate(th, "DOWNLOAD THE ZIP"))
print("art ok")
