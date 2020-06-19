#!/bin/zsh
# encoding: utf-8

# Borrowed with love from https://github.com/munki/munki/pull/986/files
# Big thanks to https://github.com/lifeunexpected

# Tip: if you get “You must first sign the relevant contracts online. (1048)” error
# Go to Apple.developer.com and sign in with the account you are trying to notarize the app with and agree to the updated license agreement.

BUNDLE_ID="com.grahamgilbert.Crypt"
BUNDLE_PKG="./Crypt.pkg"

if [[ "$1" == "" ]]; then
    echo "Couldn't find a 'Apple Developer account e-mail' as argument 1"
    exit -1
else
    AppleAcc=$1
fi
if [[ "$2" == "" ]]; then
    echo "Couldn't find an 'Apple Developer app-specific password' as argument 2"
    echo "More info at https://support.apple.com/en-us/HT204397"
    exit -1
else
    AppleAccPwd=$2
fi

# create temporary files
NOTARIZE_APP_LOG=$(mktemp -t notarize-app)
NOTARIZE_INFO_LOG=$(mktemp -t notarize-info)

# delete temporary files on exit
function finish {
	rm "$NOTARIZE_APP_LOG" "$NOTARIZE_INFO_LOG"
}
trap finish EXIT

# submit app for notarization
echo "Submitting App $BUNDLE_PKG for Notarization."
if ! xcrun altool --notarize-app --primary-bundle-id "$BUNDLE_ID" --username "$AppleAcc" --password "$AppleAccPwd" -f "$BUNDLE_PKG" > "$NOTARIZE_APP_LOG" 2>&1; then
	cat "$NOTARIZE_APP_LOG" 1>&2
	exit 1
fi

cat "$NOTARIZE_APP_LOG"
RequestUUID=$(awk -F ' = ' '/RequestUUID/ {print $2}' "$NOTARIZE_APP_LOG")

# check status periodically
while sleep 30 && date; do
echo "Waiting on Apple too approve the notarization so it can be stapled. This can take a few minutes or more. Script auto checks every 30 sec"
	# check notarization status

	if ! xcrun altool --notarization-info "$RequestUUID" --username "$AppleAcc" --password "$AppleAccPwd" > "$NOTARIZE_INFO_LOG" 2>&1; then
		cat "$NOTARIZE_INFO_LOG" 1>&2
		exit 1
	fi
	cat "$NOTARIZE_INFO_LOG"

	# once notarization is complete, run stapler and exit
	if ! grep -q "Status: in progress" "$NOTARIZE_INFO_LOG"; then
		xcrun stapler staple "$BUNDLE_PKG"
		exit $?
	fi

done
