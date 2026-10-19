# docs/demo.gif: overview, logs, capture, privacy tab (see docs/demo/Dockerfile)
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
Type "unset NO_COLOR; export COLORTERM=truecolor; clear; lazyios --demo"
Enter
Sleep 3s
Show

# overview with the logo
Sleep 2500ms

# logs
Type "2"
Sleep 3s

# capture from the network tab
Type "5"
Sleep 1s
Space
Sleep 3s

# who talks to whom
Type "7"
Sleep 4500ms
Down
Sleep 400ms
Down
Sleep 400ms
Down
Sleep 1s

# trackers only
Type "t"
Sleep 3500ms

Type "q"
Sleep 500ms
