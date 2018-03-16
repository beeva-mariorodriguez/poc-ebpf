#!/usr/bin/python
from bcc import BPF
import ctypes as ct
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("pid")
args = parser.parse_args() 

with open('./spy.c', 'r') as f:
  bpf_text = f.read()

bpf_text = bpf_text.replace('FILTER', 'if (pid != %s && ppid != %s) { return 0; }' % (args.pid, args.pid))
b = BPF(text=bpf_text)
b.attach_kprobe(event="do_sys_open", fn_name="trace_open")

NAME_MAX = 255 # linux/limits.h
class Event(ct.Structure):
    _fields_ = [("fname", ct.c_char * NAME_MAX),
                ("pid", ct.c_uint),
                ("ppid", ct.c_uint)]

print "tracing %s" % args.pid

def print_event(cpu,data,size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    print "fname: %s, pid: %d, ppid: %d" % (event.fname, event.pid, event.ppid)

b["events"].open_perf_buffer(print_event)
while True:
    b.kprobe_poll()
