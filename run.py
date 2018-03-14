#!/usr/bin/env python3
"""
show pid before running program
"""

import tempfile
import urllib.request
import subprocess
import os
import argparse

def download_script(url):
    """
    download script to a temporal directory
    """
    tmpdir = tempfile.mkdtemp()
    dest = tmpdir + "/script.sh"
    urllib.request.urlretrieve(url, dest)
    os.chmod(dest, 0o700)
    return dest

def run_script(path):
    """
    run downloaded script
    """
    def wait_for_input():
        """
        wait for user input before starting the script
        """
        def _wait_for_input():
            print("pid: " + str(os.getpid()))
            print("press ENTER to run the installer")
            input()
        return _wait_for_input

    return subprocess.Popen(
        ['sh', '-c', path],
        preexec_fn=wait_for_input()
    )

def main():
    """
    main()
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--local", help="run local script", action="store_true")
    parser.add_argument("url")
    args = parser.parse_args()
    if args.local:
        path = args.url
    else:
        path = download_script(args.url)
    process = run_script(path)
    process.wait()

if __name__ == "__main__":
    main()
