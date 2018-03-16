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

## spy.py

* trace open() calls from a process and its children (not grandchildren!)
* eBPF code is in spy.c

### example:
26232 is a bash shell's PID
```bash
./spy.py  26232
```

if I run cat .profile on the shell ...
```
fname: /etc/ld.so.cache, pid: 26576, ppid: 26232
fname: /lib/x86_64-linux-gnu/libc.so.6, pid: 26576, ppid: 26232
fname: /usr/lib/locale/locale-archive, pid: 26576, ppid: 26232
fname: .profile, pid: 26576, ppid: 26232
```

### requirements
* python 3

