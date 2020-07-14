#!/bin/zsh
# builds the package and notarizes
# requires a config.mk file in the same directory with some variables defined like below.

# DEV_INSTALL_CERT=Developer ID Installer: Example, Inc (ABCDEF12345)
# DEV_APP_CERT=Developer ID Application: Example, Inc (ABCDEF12345)
# APPLE_ACC_USER=your_apple_dev_email@example.com
# APPLE_ACC_PWD=your-one-time-app-password

sudo make pkg
sudo make notarize
