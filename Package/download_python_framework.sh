#!/bin/zsh
# Build script for Python 3 framework for Crypt
TOOLSDIR="/Library/Crypt"
PYTHON_VERSION=3.9.5
PYTHON_SHORT_VERSION=3.9

# build the framework
/tmp/relocatable-python/make_relocatable_python_framework.py \
    --python-version "${PYTHON_VERSION}" \
    --pip-requirements requirements.txt \
    --destination "${TOOLSDIR}" \
    --os-version 11


# confirm truly universal
TOTAL_DYLIB=$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.dylib" | /usr/bin/wc -l | /usr/bin/xargs)
UNIVERSAL_DYLIB=$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.dylib" | /usr/bin/xargs file | /usr/bin/grep "2 architectures" | /usr/bin/wc -l | /usr/bin/xargs)
if [ "${TOTAL_DYLIB}" != "${UNIVERSAL_DYLIB}" ] ; then
  echo "Dynamic Libraries do not match, resulting in a non-universal Python framework."
  echo "Total Dynamic Libraries found: ${TOTAL_DYLIB}"
  echo "Universal Dynamic Libraries found: ${UNIVERSAL_DYLIB}"
  exit 1
fi

echo "Dynamic Libraries are confirmed as universal"

TOTAL_SO=$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.so" | /usr/bin/wc -l | /usr/bin/xargs)
UNIVERSAL_SO=$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.so" | /usr/bin/xargs file | /usr/bin/grep "2 architectures" | /usr/bin/wc -l | /usr/bin/xargs)
if [ "${TOTAL_SO}" != "${UNIVERSAL_SO}" ] ; then
  echo "Shared objects do not match, resulting in a non-universal Python framework."
  echo "Total shared objects found: ${TOTAL_SO}"
  echo "Universal shared objects found: ${UNIVERSAL_SO}"
  UNIVERSAL_SO_ARRAY=("${(@f)$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.so" | /usr/bin/xargs file | /usr/bin/grep "2 architectures"  | awk '{print $1;}' | sed 's/:*$//g')}")
  TOTAL_SO_ARRAY=("${(@f)$(/usr/bin/find "$TOOLSDIR/Python.framework/Versions/Current/lib" -name "*.so" )}")
  echo ${TOTAL_SO_ARRAY[@]} ${UNIVERSAL_SO_ARRAY[@]} | tr ' ' '\n' | sort | uniq -u
  exit 1
fi

echo "Shared objects are confirmed as universal"

# DEV_APP_CERT=$1

# echo "Codesign the Python Framework..."

# /usr/libexec/PlistBuddy -c "Add :com.apple.security.cs.allow-unsigned-executable-memory bool true" ${TOOLSDIR}/entitlements.plist

# /usr/libexec/PlistBuddy -c "Add :com.apple.security.cs.allow-jit bool true" ${TOOLSDIR}/entitlements.plist

# find ${TOOLSDIR}/Python.framework -name '*.pyc' -delete

# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/lib/ -type f -perm -u=x -exec codesign --force --deep --verbose -s "${DEV_APP_CERT}" {} \;
# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/bin/ -type f -perm -u=x -exec codesign --force --options runtime --entitlements ${TOOLSDIR}/entitlements.plist --deep --verbose -s "${DEV_APP_CERT}" {} \;
# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/lib/ -type f -name "*dylib" -exec codesign --force --deep --verbose -s "${DEV_APP_CERT}" {} \;
# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/lib/ -type f -name "*so" -exec codesign --force --deep --verbose -s "${DEV_APP_CERT}" {} \;
# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/lib/ -type f -name "*libitclstub*" -exec codesign --force --deep --verbose -s "${DEV_APP_CERT}" {} \;
# find ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/lib/ -type f -name "*.o" -exec codesign --force --deep --verbose -s "${DEV_APP_CERT}" {} \;

# codesign --force --options runtime --entitlements ${TOOLSDIR}/entitlements.plist --deep --verbose -s "${DEV_APP_CERT}" ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/Resources/Python.app/
# codesign --force --options runtime --entitlements ${TOOLSDIR}/entitlements.plist --deep --verbose -s "${DEV_APP_CERT}" ${TOOLSDIR}/Python.framework/Versions/${PYTHON_SHORT_VERSION}/bin/python${PYTHON_SHORT_VERSION}
# codesign --force --options runtime --entitlements ${TOOLSDIR}/entitlements.plist --deep --verbose -s "${DEV_APP_CERT}" ${TOOLSDIR}/Python.framework

# # find ${TOOLSDIR}/Python.framework/Versions/Current/bin/ -type f -perm -u=x -exec codesign --timestamp --options runtime --force --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" {} \;
# # codesign --timestamp --options runtime --force --deep --verbose -s "$DEV_APP_CERT" ${TOOLSDIR}/Python.framework/Versions/Current/Python
# # find ${TOOLSDIR}/Python.framework/Versions/Current/lib/ -type f -perm -u=x -exec codesign --timestamp --options runtime --force --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" {} \;
# # find ${TOOLSDIR}/Python.framework/Versions/Current/lib/ -type f -name "*dylib" -exec codesign --force --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" {} \;

# # codesign --timestamp --options runtime --force --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" $TOOLSDIR/Python.framework/Versions/Current/Resources/Python.app/
# # codesign --timestamp --options runtime --force --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" $TOOLSDIR/Python.framework/Versions/Current/Python
# # codesign --timestamp --options runtime --force --deep --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" $TOOLSDIR/Python.framework/Versions/Current/bin/*
# # codesign --timestamp --options runtime --force --deep --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" $TOOLSDIR/Python.framework/Versions/Current/lib/*
# # codesign --timestamp --options runtime --force --deep --deep --verbose --preserve-metadata=identifier,entitlements,flags,runtime -s "$DEV_APP_CERT" $TOOLSDIR/Python.framework/Versions/Current/Python
# # codesign --timestamp --options runtime --force --deep --verbose -s  "$DEV_APP_CERT" $TOOLSDIR/Python.framework