#!/bin/zsh
# Build script for Python 3 framework for Sal scripts
TOOLSDIR=$(dirname "$0")
PYTHON_VERSION=3.8.2

# build the framework
/tmp/relocatable-python/make_relocatable_python_framework.py \
    --python-version "${PYTHON_VERSION}" \
    --pip-requirements requirements.txt \
    --destination "${TOOLSDIR}"

DevApp=$1

# sign all the bits of python with our Apple Developer ID Installer: cert.
find ${TOOLSDIR}/Python.framework -name '*.pyc' -delete
find ${TOOLSDIR}/Python.framework/Versions/3.8/lib/ -type f -perm -u=x -exec codesign --force --deep --verbose -s "$DevApp" {} \;
find ${TOOLSDIR}/Python.framework/Versions/3.8/bin/ -type f -perm -u=x -exec codesign --force --deep --verbose -s "$DevApp" {} \;
find ${TOOLSDIR}/Python.framework/Versions/3.8/lib/ -type f -name "*dylib" -exec codesign --force --deep --verbose -s "$DevApp" {} \;

/usr/libexec/PlistBuddy -c "Add :com.apple.security.cs.allow-unsigned-executable-memory bool true" ${TOOLSDIR}/entitlements.plist

codesign --force --options runtime --entitlements $TOOLSDIR/entitlements.plist --deep --verbose -s "$DevApp" $TOOLSDIR/Python.framework/Versions/3.8/Resources/Python.app/
codesign --force --deep --options runtime --entitlements $TOOLSDIR/entitlements.plist --deep --verbose -s "$DevApp" $TOOLSDIR/Python.framework/Versions/3.8/bin/*
codesign --force --deep --options runtime --entitlements $TOOLSDIR/entitlements.plist --deep --verbose -s "$DevApp" $TOOLSDIR/Python.framework/Versions/3.8/lib/*
codesign --force --deep --options runtime --entitlements $TOOLSDIR/entitlements.plist --deep --verbose -s "$DevApp" $TOOLSDIR/Python.framework/Versions/3.8/Python
codesign --force --deep --verbose -s  "$DevApp" $TOOLSDIR/Python.framework
