include /usr/local/share/luggage/luggage.make
TITLE=Crypt
GITVERSION=$(shell ./build_no.sh)
PACKAGE_VERSION=2.1.2.${GITVERSION}
REVERSE_DOMAIN=com.grahamgilbert
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
