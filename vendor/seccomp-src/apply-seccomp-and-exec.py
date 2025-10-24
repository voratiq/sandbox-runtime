#!/usr/bin/env python3
"""
Apply seccomp filter and exec command

This helper script loads a compiled seccomp BPF filter, applies it to the
current process using prctl, and then execs the specified command. This enables
two-stage seccomp application: infrastructure code runs without the filter,
then the user command runs with the filter active.

Usage:
  ./apply-seccomp-and-exec.py <filter-file> -- <command> [args...]

The filter file should contain a compiled BPF program (struct sock_fprog).
"""

import sys
import os
import ctypes
import ctypes.util

# Constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

# Define sock_filter structure (8 bytes)
class sock_filter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]

# Define sock_fprog structure
class sock_fprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(sock_filter)),
    ]

def load_filter(path):
    """Load BPF filter from file"""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except IOError as e:
        print(f"Error: Failed to open filter file {path}: {e}", file=sys.stderr)
        sys.exit(1)

    # Verify size is valid
    filter_size = ctypes.sizeof(sock_filter)
    if len(data) == 0 or len(data) % filter_size != 0:
        print(f"Error: Invalid filter file size: {len(data)}", file=sys.stderr)
        sys.exit(1)

    # Parse filter data into array
    num_filters = len(data) // filter_size
    filter_array = (sock_filter * num_filters)()
    ctypes.memmove(filter_array, data, len(data))

    # Create fprog structure
    prog = sock_fprog()
    prog.len = num_filters
    prog.filter = ctypes.cast(filter_array, ctypes.POINTER(sock_filter))

    return prog, filter_array  # Keep array alive

def main():
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <filter-file> -- <command> [args...]", file=sys.stderr)
        print("\nApplies seccomp filter and execs the command", file=sys.stderr)
        sys.exit(1)

    # Check for separator
    if sys.argv[2] != '--':
        print("Error: Expected '--' as second argument", file=sys.stderr)
        sys.exit(1)

    filter_path = sys.argv[1]
    command_argv = sys.argv[3:]

    # Load the BPF filter
    prog, filter_array = load_filter(filter_path)

    # Load libc
    libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

    # Set no_new_privs (required for unprivileged processes)
    ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret < 0:
        errno = ctypes.get_errno()
        print(f"Error: Failed to set no_new_privs: {os.strerror(errno)}", file=sys.stderr)
        sys.exit(1)

    # Apply the seccomp filter
    ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    if ret < 0:
        errno = ctypes.get_errno()
        print(f"Error: Failed to apply seccomp filter: {os.strerror(errno)}", file=sys.stderr)
        sys.exit(1)

    # Filter is now active - exec the command
    try:
        os.execvp(command_argv[0], command_argv)
    except OSError as e:
        print(f"Error: Failed to exec {command_argv[0]}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
