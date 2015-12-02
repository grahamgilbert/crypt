include /usr/local/share/luggage/luggage.make

TITLE=Crypt
PACKAGE_VERSION=2.0
REVERSE_DOMAIN=com.grahamgilbert
PAYLOAD=\
			pack-plugin\
			pack-script-postinstall\
			pack-script-preinstall

#################################################

build: clean-crypt
	xcodebuild -project Crypt/Crypt.xcodeproj -configuration Release

clean-crypt:
	rm -rf Crypt/build

pack-plugin: build
	@sudo mkdir -p ${WORK_D}/Library/Security/SecurityAgentPlugins
	@sudo ${CP} -R Crypt/build/Release/Crypt.bundle ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle
