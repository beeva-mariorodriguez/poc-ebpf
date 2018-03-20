#!/usr/bin/python
from bcc import BPF
import ctypes as ct
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("pid")
args = parser.parse_args() 

# read ebpf C code to bpf_text
with open('./spy.c', 'r') as f:
  bpf_text = f.read()

# replace the placeholder (FILTER) with a check
bpf_text = bpf_text.replace('FILTER', 'if (pid != %s && ppid != %s) { return 0; }' % (args.pid, args.pid))
b = BPF(text=bpf_text)

NAME_MAX = 255 # linux/limits.h

# event definition, should be compatible with enum event_type and struct event_t from spy.c
class EventType(object):
    OPEN = 0
    EXEC = 1

class Event(ct.Structure):
    _fields_ = [("type", ct.c_int),
                ("fname", ct.c_char * NAME_MAX),
                ("pid", ct.c_uint),
                ("ppid", ct.c_uint)]

print "tracing %s" % args.pid

def print_event(cpu,data,size):
    event = ct.cast(data, ct.POINTER(Event)).contents
    if event.type == EventType.OPEN:
        print "%d->%d > open(%s)" % (event.ppid, event.pid, event.fname)
    if event.type == EventType.EXEC:
        print "%d->%d > exec(%s)" % (event.ppid, event.pid, event.fname)


b["events"].open_perf_buffer(print_event)

while True:
    b.kprobe_poll()
