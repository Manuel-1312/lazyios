"""Palette and the textual theme."""

from textual.theme import Theme

BLACK = "#000000"
BONE = "#e6e2d3"
ACID = "#b6ff00"
RED = "#ff3030"
GRAY = "#8a8a82"
DIM = "#55554f"
PANEL = "#0b0b0a"

UNDERGROUND = Theme(
    name="underground",
    primary=ACID,
    secondary=GRAY,
    accent=ACID,
    warning=RED,
    error=RED,
    success=ACID,
    foreground=BONE,
    background=BLACK,
    surface=BLACK,
    panel=PANEL,
    dark=True,
    variables={
        "block-cursor-background": ACID,
        "block-cursor-foreground": BLACK,
        "block-cursor-blurred-background": DIM,
        "block-cursor-blurred-foreground": BONE,
        "block-cursor-text-style": "bold",
        "footer-key-foreground": ACID,
        "footer-description-foreground": GRAY,
        "footer-background": BLACK,
        "input-cursor-background": ACID,
        "input-cursor-foreground": BLACK,
        "input-selection-background": f"{ACID} 30%",
        "scrollbar": DIM,
        "scrollbar-hover": GRAY,
        "scrollbar-active": ACID,
        "scrollbar-background": BLACK,
        "scrollbar-background-hover": BLACK,
        "scrollbar-background-active": BLACK,
        "scrollbar-corner-color": BLACK,
        "border": DIM,
        "border-blurred": DIM,
        "text-muted": GRAY,
    },
)
