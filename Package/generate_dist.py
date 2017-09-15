#!/usr/bin/python

"""
Adds the OS check to a generated distribution file
"""

import plistlib
import os

def main():
    """
    FINAL COUNTDOWN
    """
    crypt_plist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Crypt','Info.plist')
    version = plistlib.readPlist(crypt_plist)['CFBundleShortVersionString']

    with open('Distribution-Template', 'r') as the_file:
        filedata = the_file.read()

    # Replace the target string
    filedata = filedata.replace('replace_version', version)

    # Write the file out again
    with open('Distribution', 'w') as the_file:
        the_file.write(filedata)

if __name__ == '__main__':
    main()
