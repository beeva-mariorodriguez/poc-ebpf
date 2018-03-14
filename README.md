# poc-ebpf

goal: write a script/set of scripts to check what is doing the typical curl | bash installer

it could be pretty hard to trace an interactive script in the same window it is running, so I use a script (run.py) to download and run the script showing its PID

## run.py

run a local or downloaded command/script, but pause it and show the PID before actually starting (so we have time to launch the tracing program)
### example:
```bash
./run.py https://sh.rustup.rs
pid: 15636
press ENTER to run the installer
info: downloading installer
...
```
### requirements
* python 3

