# docs/demo.gif: overview, capture, connections, privacy score, timeline, palette, audit
# (see docs/demo/Dockerfile)
Output demo.gif

Set Shell "bash"
Set FontFamily "DejaVu Sans Mono"
Set FontSize 14
Set Width 1080
Set Height 640
Set Padding 8
Set Framerate 15
Set TypingSpeed 60ms
Set Theme { "name": "underground", "black": "#000000", "red": "#ff3030", "green": "#b6ff00", "yellow": "#e6e2d3", "blue": "#8a8a82", "magenta": "#ff3030", "cyan": "#b6ff00", "white": "#e6e2d3", "brightBlack": "#55554f", "brightRed": "#ff3030", "brightGreen": "#b6ff00", "brightYellow": "#e6e2d3", "brightBlue": "#8a8a82", "brightMagenta": "#ff3030", "brightCyan": "#b6ff00", "brightWhite": "#e6e2d3", "background": "#000000", "foreground": "#e6e2d3", "selection": "#55554f", "cursor": "#b6ff00" }

Hide
Type "unset NO_COLOR; export COLORTERM=truecolor; clear; lazyios --demo --out /tmp/lazyios-demo"
Enter
Sleep 3s
Show

# overview: device, battery health
Sleep 2500ms

# start the capture from the network tab
Type "5"
Sleep 800ms
Space
Sleep 2500ms

# every connection, with its domain and how the name was learned
Type "8"
Sleep 3s
Down
Sleep 400ms
Down
Sleep 1500ms

# privacy score per app, with the reason for every point
Type "9"
Sleep 3s
Down
Sleep 2s

# trackers only, in the privacy tab
Type "7"
Sleep 1s
Type "t"
Sleep 2500ms

# the timeline of the session
Type "0"
Sleep 3s

# command palette
Ctrl+P
Sleep 800ms
Type "audit"
Sleep 1200ms
Enter
Sleep 4s
Escape
Sleep 800ms

Type "q"
Sleep 500ms
