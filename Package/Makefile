include /usr/local/share/luggage/luggage.make
PB_EXTRA_ARGS+= --info "./PackageInfo"
TITLE=Crypt
GITVERSION=$(shell ./build_no.sh)
BUNDLE_VERSION=$(shell /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "../Crypt/Info.plist")
PACKAGE_VERSION=${BUNDLE_VERSION}.${GITVERSION}
REVERSE_DOMAIN=com.grahamgilbert
PACKAGE_NAME=${TITLE}
PAYLOAD=\
			pack-plugin\
			pack-script-postinstall\
			pack-Library-LaunchDaemons-com.grahamgilbert.crypt.plist \
			pack-checkin \
			pack-script-preinstall

#################################################

build: clean-crypt
	xcodebuild -project ../Crypt.xcodeproj -configuration Release

clean-crypt:
	rm -rf ../build

pack-plugin: build
	@sudo mkdir -p ${WORK_D}/Library/Security/SecurityAgentPlugins
	@sudo ${CP} -R ../build/Release/Crypt.bundle ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle

pack-checkin: l_Library
	@sudo mkdir -p ${WORK_D}/Library/Crypt
	@sudo ${CP} checkin ${WORK_D}/Library/Crypt/checkin
	@sudo ${CP} FoundationPlist.py ${WORK_D}/Library/Crypt/FoundationPlist.py
	@sudo chown -R root:wheel ${WORK_D}/Library/Crypt
	@sudo chmod 755 ${WORK_D}/Library/Crypt/checkin

dist: pkg
	@sudo rm -f Distribution
	python generate_dist.py
	@sudo productbuild --distribution Distribution Crypt-${BUNDLE_VERSION}.pkg
	@sudo rm -f Crypt.pkg
	@sudo rm -f Distribution
