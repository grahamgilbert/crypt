#!/usr/bin/python
import plistlib
import subprocess
from Foundation import *
from AppKit import *
from Cocoa import *
import argparse
import sys

parser = argparse.ArgumentParser(description='Run FDESetup enable')
parser.add_argument('--username',
                    help='Username to use')

parser.add_argument('--password',
                    help='password to use')


args = parser.parse_args()

the_settings = {}
the_settings['Username'] = args.username
the_settings['Password'] = args.password
input_plist = plistlib.writePlistToString(the_settings)

# run command
p = subprocess.Popen(['/usr/bin/fdesetup','enable','-outputplist', '-inputplist'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
(stdout_data, err) = p.communicate(input=input_plist)
if p.returncode != 0:
    NSLog('ERROR: %s' % err)
    sys.stdout.write(err)
else:
    sys.stdout.write(stdout_data)
    plistlib.writePlist(stdout_data, '/private/var/root/recovery_key.plist')