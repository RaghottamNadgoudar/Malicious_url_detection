import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch
import numpy as np

# ── Color Palette (academic & official) ──────────────────────────────────
COL_BG          = '#FFFFFF'
COL_HEADER      = '#1A237E'   # Deep Navy
COL_START_END   = '#37474F'   # Charcoal
COL_START_FILL  = '#ECEFF1'   # Light Grey
COL_PROC        = '#0D47A1'   # Strong Blue
COL_PROC_FILL   = '#F0F4C3'   # Light Blue/Green tint - wait, let's use a cleaner light blue
COL_PROC_FILL   = '#E3F2FD'   # Soft Blue
COL_DECISION    = '#E65100'   # Dark Orange/Amber
COL_DECISION_FILL = '#FFF3E0' # Soft Amber
COL_BLENDER     = '#4A148C'   # Deep Purple
COL_BLENDER_FILL= '#F3E5F5'   # Soft Purple

COL_SAFE        = '#1B5E20'   # Forest Green
COL_SAFE_FILL   = '#E8F5E9'
COL_SUSP        = '#F57F17'   # Amber
COL_SUSP_FILL   = '#FFFDE7'
COL_MAL         = '#B71C1C'   # Dark Red
COL_MAL_FILL    = '#FFEBEE'

COL_COL1_BG     = '#F5F7FA'
COL_COL2_BG     = '#F5F7FA'
COL_COL3_BG     = '#F5F7FA'
ARROW_CLR       = '#455A64'

FONT_BODY  = 'DejaVu Sans'
FS_NODE    = 8
FS_HEADER  = 12
FS_COL_HDR = 10.5

# Canvas size (16:9 ratio)
FIG_W, FIG_H = 16.0, 9.0
DPI = 180

fig, ax = plt.subplots(figsize=(FIG_W, FIG_H), dpi=DPI)
ax.set_xlim(0, FIG_W)
ax.set_ylim(0, FIG_H)
ax.axis('off')
ax.set_facecolor(COL_BG)
fig.patch.set_facecolor(COL_BG)

# Title
ax.text(FIG_W/2, FIG_H - 0.4, 
        'System Architecture: 7-Phase Hybrid AI Malicious URL Detection Pipeline',
        ha='center', va='top', fontsize=FS_HEADER+2, fontfamily=FONT_BODY,
        fontweight='bold', color=COL_HEADER)

# Subtitle / Line
ax.plot([0.5, FIG_W - 0.5], [FIG_H - 0.7, FIG_H - 0.7], color=COL_HEADER, linewidth=1.5, alpha=0.8)

# Layout constants
COL_W = 4.4
GAP = 0.8
LEFT_M = 0.8
TOP_Y = FIG_H - 1.0
BOT_Y = 1.0

# Column x-coordinates
CX = [
    LEFT_M + COL_W/2,
    LEFT_M + COL_W + GAP + COL_W/2,
    LEFT_M + 2*COL_W + 2*GAP + COL_W/2
]
CL = [
    LEFT_M,
    LEFT_M + COL_W + GAP,
    LEFT_M + 2*COL_W + 2*GAP
]

# Draw Column Backgrounds
col_names = [
    ("COLUMN 1: URL Pre-Processing", "Phases 0–1"),
    ("COLUMN 2: Feature & ML Analysis", "Phases 2–4"),
    ("COLUMN 3: Verification & Verdict", "Phases 5–7")
]

for i in range(3):
    # Column box
    rect = FancyBboxPatch(
        (CL[i], BOT_Y), COL_W, TOP_Y - BOT_Y,
        boxstyle='round,pad=0,rounding_size=0.15',
        facecolor='#F8F9FA', edgecolor='#CFD8DC',
        linewidth=1.2, zorder=1
    )
    ax.add_patch(rect)
    
    # Header area
    hdr_h = 0.5
    hbar = FancyBboxPatch(
        (CL[i], TOP_Y - hdr_h), COL_W, hdr_h,
        boxstyle='round,pad=0,rounding_size=0.15',
        facecolor=COL_HEADER, edgecolor=COL_HEADER,
        linewidth=0, zorder=2
    )
    ax.add_patch(hbar)
    
    # Text in header
    ax.text(CX[i], TOP_Y - hdr_h/2, col_names[i][0],
            ha='center', va='center', fontsize=FS_COL_HDR,
            fontfamily=FONT_BODY, fontweight='bold', color='white', zorder=3)
    ax.text(CL[i] + 0.15, TOP_Y - hdr_h/2, col_names[i][1],
            ha='left', va='center', fontsize=8,
            fontfamily=FONT_BODY, color='#E0E0E0', zorder=3)

# ── Node Coordinates ────────────────────────────────────────────────────────
# 4 Levels inside each column
L_Y = [
    TOP_Y - 1.1,  # Level 1
    TOP_Y - 2.5,  # Level 2
    TOP_Y - 3.9,  # Level 3
    TOP_Y - 5.3   # Level 4
]

BX_W = 3.8
BX_H = 0.7

# Helpers
def draw_box(cx, cy, text, fill, edge, bold=False, radius=0.1, z=3):
    box = FancyBboxPatch(
        (cx - BX_W/2, cy - BX_H/2), BX_W, BX_H,
        boxstyle=f"round,pad=0,rounding_size={radius}",
        facecolor=fill, edgecolor=edge, linewidth=1.2, zorder=z
    )
    ax.add_patch(box)
    weight = 'bold' if bold else 'normal'
    ax.text(cx, cy, text, ha='center', va='center',
            fontsize=FS_NODE, fontfamily=FONT_BODY, fontweight=weight,
            color=edge, zorder=z+1)

def draw_diamond(cx, cy, text, fill, edge):
    w, h = 2.4, 0.7
    pts = np.array([
        [cx, cy+h/2], [cx+w/2, cy], [cx, cy-h/2], [cx-w/2, cy]
    ])
    patch = plt.Polygon(pts, closed=True, facecolor=fill,
                        edgecolor=edge, linewidth=1.2, zorder=3)
    ax.add_patch(patch)
    ax.text(cx, cy, text, ha='center', va='center',
            fontsize=FS_NODE-0.5, fontfamily=FONT_BODY, fontweight='bold',
            color=edge, zorder=4)

def draw_oval(cx, cy, w, h, text, fill, edge, bold=True):
    ell = mpatches.Ellipse((cx, cy), w, h, facecolor=fill,
                           edgecolor=edge, linewidth=1.5, zorder=3)
    ax.add_patch(ell)
    weight = 'bold' if bold else 'normal'
    ax.text(cx, cy, text, ha='center', va='center',
            fontsize=FS_NODE, fontfamily=FONT_BODY, color=edge,
            fontweight=weight, zorder=4)

def draw_arrow(x1, y1, x2, y2, label='', color=ARROW_CLR, style='solid', arrow_style='->', lw=1.1):
    ls = '-' if style == 'solid' else '--'
    ax.annotate('',
        xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(
            arrowstyle=arrow_style, color=color, lw=lw, ls=ls,
            connectionstyle='arc3,rad=0.0'
        ), zorder=5)
    if label:
        mx, my = (x1+x2)/2, (y1+y2)/2
        ax.text(mx + 0.08, my, label, fontsize=7, color=color,
                fontfamily=FONT_BODY, fontweight='bold', va='center', zorder=6)

# ── Draw Nodes ──────────────────────────────────────────────────────────────

# Column 1
draw_oval(CX[0], L_Y[0], 2.2, 0.5, 'Input URL', COL_START_FILL, COL_START_END)
draw_diamond(CX[0], L_Y[1], 'URL Shortened?', COL_DECISION_FILL, COL_DECISION)
draw_box(CX[0], L_Y[2], 'Phase 0: URL Expansion\nHTTP Redirect Follower (HEAD)', COL_PROC_FILL, COL_PROC)
draw_box(CX[0], L_Y[3], 'Phase 1: Graph Traversal\nBFS/DFS & Shannon Entropy', COL_PROC_FILL, COL_PROC)

# Column 2
draw_diamond(CX[1], L_Y[0], 'Entropy < 3.0?', COL_DECISION_FILL, COL_DECISION)
draw_box(CX[1], L_Y[1], 'Phase 2: Pattern Matching\nBoyer-Moore / Horspool Search', COL_PROC_FILL, COL_PROC)
draw_box(CX[1], L_Y[2], 'Phase 3: Deep Neural Network\n15-Feature Input Vector', COL_PROC_FILL, COL_PROC)
draw_box(CX[1], L_Y[3], 'Phase 4: Dijkstra Shortest Path\nThreat Candidate Graph Tracing', COL_PROC_FILL, COL_PROC)

# Column 3
draw_box(CX[2], L_Y[0], 'Phase 5: Bloom Filter + LSH\nMurmurHash3 & MinHash Signatures', COL_PROC_FILL, COL_PROC)
draw_box(CX[2], L_Y[1], 'Phase 6: Heapsort + Huffman\nThreat Candidate Ranking Baseline', COL_PROC_FILL, COL_PROC)
draw_box(CX[2], L_Y[2], 'Phase 7: Reachability Analysis\nTransitive Closure (BFS Matrix)', COL_PROC_FILL, COL_PROC)
draw_box(CX[2], L_Y[3], 'Score Blender\nNeural Prob. · Whitelist · Redirects', COL_BLENDER_FILL, COL_BLENDER, bold=True)

# Verdicts (Level 4.8 / bottom)
Y_V = BOT_Y + 0.6
draw_oval(CX[2] - 1.2, Y_V, 1.0, 0.45, 'SAFE\n(< 25%)', COL_SAFE_FILL, COL_SAFE)
draw_oval(CX[2], Y_V, 1.1, 0.45, 'SUSPICIOUS\n(25% - 75%)', COL_SUSP_FILL, COL_SUSP)
draw_oval(CX[2] + 1.2, Y_V, 1.0, 0.45, 'MALICIOUS\n(> 75%)', COL_MAL_FILL, COL_MAL)

# ── Draw Connections ────────────────────────────────────────────────────────

# Col 1: Input -> Shortened?
draw_arrow(CX[0], L_Y[0]-0.25, CX[0], L_Y[1]+0.35)

# Col 1: Shortened? -> Yes -> Phase 0
draw_arrow(CX[0], L_Y[1]-0.35, CX[0], L_Y[2]+0.35, label='Yes')

# Col 1: Shortened? -> No -> Phase 1 (Bypass Phase 0)
# Route arrow around the left of the column to look professional
ax.plot([CX[0] - 1.2, CX[0] - 2.0, CX[0] - 2.0, CX[0] - 1.9],
        [L_Y[1], L_Y[1], L_Y[3], L_Y[3]], color=COL_DECISION, lw=1.1, zorder=5)
# Draw arrow head
draw_arrow(CX[0] - 1.9, L_Y[3], CX[0] - BX_W/2, L_Y[3], color=COL_DECISION)
ax.text(CX[0] - 1.9, L_Y[1] + 0.1, 'No', fontsize=7, color=COL_DECISION, fontfamily=FONT_BODY, fontweight='bold')

# Col 1: Phase 0 -> Phase 1
draw_arrow(CX[0], L_Y[2]-0.35, CX[0], L_Y[3]+0.35)

# Col 1 Bottom -> Col 2 Top: Phase 1 -> Entropy < 3.0?
# Route from bottom of Phase 1, right, up, and into top of Col 2
ax.plot([CX[0], CX[0], CX[1], CX[1]],
        [L_Y[3]-0.35, L_Y[3]-0.6, L_Y[0]+0.6, L_Y[0]+0.35], color=ARROW_CLR, lw=1.1, zorder=5)
# Draw arrow head into Col 2 top
draw_arrow(CX[1], L_Y[0]+0.4, CX[1], L_Y[0]+0.35, arrow_style='->')

# Col 2: Entropy -> No -> Phase 2
draw_arrow(CX[1], L_Y[0]-0.35, CX[1], L_Y[1]+0.35, label='No')

# Col 2: Phase 2 -> Phase 3 -> Phase 4
draw_arrow(CX[1], L_Y[1]-0.35, CX[1], L_Y[2]+0.35)
draw_arrow(CX[1], L_Y[2]-0.35, CX[1], L_Y[3]+0.35)

# Col 2 Bottom -> Col 3 Top: Phase 4 -> Phase 5
# Route from bottom of Phase 4, right, up, and into top of Col 3
ax.plot([CX[1], CX[1], CX[2], CX[2]],
        [L_Y[3]-0.35, L_Y[3]-0.6, L_Y[0]+0.6, L_Y[0]+0.35], color=ARROW_CLR, lw=1.1, zorder=5)
draw_arrow(CX[2], L_Y[0]+0.4, CX[2], L_Y[0]+0.35, arrow_style='->')

# Col 3: Phase 5 -> Phase 6 -> Phase 7 -> Score Blender
draw_arrow(CX[2], L_Y[0]-0.35, CX[2], L_Y[1]+0.35)
draw_arrow(CX[2], L_Y[1]-0.35, CX[2], L_Y[2]+0.35)
draw_arrow(CX[2], L_Y[2]-0.35, CX[2], L_Y[3]+0.35)

# Col 3: Score Blender -> Verdicts
draw_arrow(CX[2] - 0.5, L_Y[3]-0.35, CX[2] - 1.2, Y_V+0.225, color=COL_SAFE)
draw_arrow(CX[2], L_Y[3]-0.35, CX[2], Y_V+0.225, color=COL_SUSP)
draw_arrow(CX[2] + 0.5, L_Y[3]-0.35, CX[2] + 1.2, Y_V+0.225, color=COL_MAL)

# Col 2 Top (Entropy Yes) -> Fast-Track -> Score Blender
# Route from right side of Entropy diamond, right, down, and enter left of Score Blender
ax.plot([CX[1] + 1.2, CX[2] - BX_W/2 - 0.25, CX[2] - BX_W/2 - 0.25],
        [L_Y[0], L_Y[0], L_Y[3]], color='#6A1B9A', ls='--', lw=1.2, zorder=5)
draw_arrow(CX[2] - BX_W/2 - 0.25, L_Y[3], CX[2] - BX_W/2, L_Y[3], color='#6A1B9A', style='dashed')
ax.text(CX[1] + 1.3, L_Y[0] + 0.1, 'Yes (Fast-Track)', fontsize=7, color='#6A1B9A', fontfamily=FONT_BODY, fontweight='bold')

# Legend at the very bottom
lx = LEFT_M
ly = BOT_Y - 0.65

legend_items = [
    (COL_START_FILL, COL_START_END, 'Start / End Terminal'),
    (COL_PROC_FILL, COL_PROC, 'Standard Processing Phase'),
    (COL_DECISION_FILL, COL_DECISION, 'Decision Junction'),
    (COL_BLENDER_FILL, COL_BLENDER, 'Score Blender Engine'),
    (COL_SAFE_FILL, COL_SAFE, 'Final Verdict Outflows')
]

for idx, (fill, edge, text) in enumerate(legend_items):
    bx = lx + idx * 2.9
    rect = FancyBboxPatch(
        (bx, ly), 0.3, 0.2,
        boxstyle='round,pad=0,rounding_size=0.04',
        facecolor=fill, edgecolor=edge, linewidth=1.0, zorder=6
    )
    ax.add_patch(rect)
    ax.text(bx + 0.38, ly + 0.1, text, va='center', fontsize=7.5,
            fontfamily=FONT_BODY, color='#37474F', zorder=6)

ax.text(LEFT_M, ly - 0.2,
        'Note: Dashed route represents the fast-track lane for low-suspicion/low-entropy URLs, bypassing deep feature extraction to optimize system latency.',
        fontsize=7, color='#546E7A', fontfamily=FONT_BODY, va='top', zorder=6)

# Output files
out_png = 'architecture_flowchart.png'
out_pdf = 'architecture_flowchart_report.pdf'

plt.tight_layout(pad=0)
fig.savefig(out_png, dpi=DPI, bbox_inches='tight', facecolor=COL_BG, format='png')
fig.savefig(out_pdf, bbox_inches='tight', facecolor=COL_BG, format='pdf')

print("Successfully generated new vertical-grid balanced flowchart!")
