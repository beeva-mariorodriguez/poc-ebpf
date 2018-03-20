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

## shellspy.py

* trace open(), clone() and exec() calls from a process and its children (not grandchildren!)
* eBPF code is in shellspy.c

### example:
26232 is a bash shell's PID
```bash
./shellspy.py  14914
```

if I run cat .profile on the shell ...
```
tracing 16216
pid: 16216 ppid: 16053 > clone()
pid: 16361 ppid: 16216 > exec(/bin/cat)
pid: 16361 ppid: 16216 > open(/etc/ld.so.cache)
pid: 16361 ppid: 16216 > open(/lib/x86_64-linux-gnu/libc.so.6)
pid: 16361 ppid: 16216 > open(/usr/lib/locale/locale-archive)
pid: 16361 ppid: 16216 > open(.profile)
```

### requirements
* run.py: python 3
* shellspy: python2, bcc headers

