# VHS tape for recording an animated GIF of Upstream Check
# Run locally with: vhs docs/demo.tape
Output docs/assets/demo.gif

Set FontSize 15
Set Width 900
Set Height 560
Set Theme "GitHub Dark"
Set Padding 20

Type "pipx install upstream-check"
Enter
Sleep 1s

Type "upstream-check init https://example.org/data.csv --name air-quality"
Enter
Sleep 1.5s

Type "upstream-check check"
Enter
Sleep 4s
