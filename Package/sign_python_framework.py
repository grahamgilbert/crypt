#!/usr/bin/env python3

# encoding: utf-8
"""
Based on https://github.com/ox-it/munki-rebrand


Original license is below

Copyright (C) University of Oxford 2016-21
    Ben Goodstein <ben.goodstein at it.ox.ac.uk>

Based on an original script by Arjen van Bochoven

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import subprocess
import os
import stat
import shutil
from tempfile import mkdtemp
import plistlib
import argparse
import sys
import atexit

PYTHON_VERSION = "3.9.6"
SHORT_PYTHON_VERSION = "3.9"
# TOOLS_DIR = os.path.dirname(os.path.realpath(__file__))
TOOLS_DIR = "/Library/Crypt"


PY_FWK = os.path.join(TOOLS_DIR, "Python.Framework")
PY_CUR = os.path.join(PY_FWK, "Versions/Current")


PRODUCTSIGN = "/usr/bin/productsign"
CODESIGN = "/usr/bin/codesign"

global verbose
verbose = False
tmp_dir = mkdtemp()


@atexit.register
def cleanup():
    print("Cleaning up...")
    try:
        shutil.rmtree(tmp_dir)
    # In case subprocess cleans up before we do
    except OSError:
        pass
    print("Done.")


def run_cmd(cmd, ret=None):
    """Runs a command passed in as a list. Can also be provided with a regex
    to search for in the output, returning the result"""
    if verbose:
        print(f"Running command {cmd}")
    proc = subprocess.run(cmd, capture_output=True)
    if verbose and proc.stdout != b"" and not ret:
        print(proc.stdout.rstrip().decode())
    if proc.returncode != 0:
        print(proc.stderr.rstrip().decode())
        sys.exit(1)
    if ret:
        return proc.stdout.rstrip().decode()


def sign_package(signing_id, pkg):
    """Signs a pkg with a signing id"""
    cmd = [PRODUCTSIGN, "--sign", signing_id, pkg, f"{pkg}-signed"]
    print("Signing pkg...")
    run_cmd(cmd)
    print(f"Moving {pkg}-signed to {pkg}...")
    os.rename(f"{pkg}-signed", pkg)


def sign_binary(
    signing_id,
    binary,
    verbose=False,
    deep=False,
    options=[],
    entitlements="",
    force=False,
):
    """Signs a binary with a signing id, with optional arguments for command line
    args"""
    cmd = [CODESIGN, "--timestamp", "--sign", signing_id]
    if force:
        cmd.append("--force")
    if deep:
        cmd.append("--deep")
    if verbose:
        cmd.append("--verbose")
    if entitlements:
        cmd.append("--entitlements")
        cmd.append(entitlements)
    if options:
        cmd.append("--options")
        cmd.append(",".join([option for option in options]))
    cmd.append(binary)
    run_cmd(cmd)


def is_signable_bin(path):
    """Checks if a path is a file and is executable"""
    if os.path.isfile(path) and (os.stat(path).st_mode & stat.S_IXUSR > 0):
        return True
    return False


def is_signable_lib(path):
    """Checks if a path is a file and ends with .so or .dylib"""
    if os.path.isfile(path) and (path.endswith(".so") or path.endswith(".dylib")):
        return True
    return False


def main():
    p = argparse.ArgumentParser(description="Builds and signs Python")

    p.add_argument(
        "-S",
        "--sign-binaries",
        action="store",
        default=None,
        help="A Developer ID Application certificate from keychain. "
        "Provide the certificate's Common Name. e.g.: "
        "'Developer ID Application  Munki (U8PN57A5N2)'",
    ),
    p.add_argument("-v", "--verbose", action="store_true", help="Be more verbose"),

    args = p.parse_args()

    if os.geteuid() != 0:
        print(
            "You must run this script as root in order to build your new "
            "Python installer pkg!"
        )
        sys.exit(1)

    if not args.sign_binaries:
        print("You must specify a signing identity")
        sys.exit(1)

    global verbose
    verbose = args.verbose

    root_dir = os.path.join(TOOLS_DIR, "Python.framework")
    # Set root:admin throughout payload
    for root, dirs, files in os.walk(root_dir):
        for dir_ in dirs:
            os.chown(os.path.join(root, dir_), 0, 80)
        for file_ in files:
            os.chown(os.path.join(root, file_), 0, 80)

    # Generate entitlements file for later
    entitlements = {
        "com.apple.security.cs.allow-unsigned-executable-memory": True,
        "com.apple.security.cs.allow-jit": True,
        "com.apple.security.cs.allow-dyld-environment-variables": True,
        "com.apple.security.cs.disable-library-validation": True,
    }

    ent_file = os.path.join(tmp_dir, "entitlements.plist")
    with open(ent_file, "wb") as f:
        plistlib.dump(entitlements, f)

    binaries = []
    # Add the executable libs and bins in python pkg
    pylib = os.path.join(root_dir, PY_CUR, "lib")
    pybin = os.path.join(root_dir, PY_CUR, "bin")
    for pydir in pylib, pybin:
        binaries.extend(
            [
                os.path.join(pydir, f)
                for f in os.listdir(pydir)
                if is_signable_bin(os.path.join(pydir, f))
            ]
        )
        for root, dirs, files in os.walk(pydir):
            for file_ in files:
                if is_signable_lib(os.path.join(root, file_)):
                    binaries.append(os.path.join(root, file_))

    # Add binaries which need entitlements
    entitled_binaries = [
        os.path.join(root_dir, PY_CUR, "Resources/Python.app"),
        os.path.join(pybin, "python3"),
    ]

    # Sign all the binaries. The order is important. Which is why this is a bit
    # gross
    print("Signing binaries (this may take a while)...")
    for binary in binaries:
        if verbose:
            print(f"Signing {binary}...")
        sign_binary(
            args.sign_binaries,
            binary,
            deep=True,
            force=True,
            options=["runtime"],
        )
    for binary in entitled_binaries:
        if verbose:
            print(f"Signing {binary} with entitlements from {ent_file}...")
        sign_binary(
            args.sign_binaries,
            binary,
            deep=True,
            force=True,
            options=["runtime"],
            entitlements=ent_file,
        )
    # Finally sign python framework
    py_fwkpath = os.path.join(root_dir, PY_FWK)
    if verbose:
        print(f"Signing {py_fwkpath}...")
    sign_binary(args.sign_binaries, py_fwkpath, deep=True, force=True)


if __name__ == "__main__":
    main()