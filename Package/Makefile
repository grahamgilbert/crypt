include /usr/local/share/luggage/luggage.make
include config.mk
PB_EXTRA_ARGS+= --info "./PackageInfo" --sign "${DEV_INSTALL_CERT}"
TITLE=Crypt
GITVERSION=$(shell ./build_no.sh)
BUNDLE_VERSION=$(shell /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "../Crypt/Info.plist")
PACKAGE_VERSION=${BUNDLE_VERSION}.${GITVERSION}
REVERSE_DOMAIN=com.grahamgilbert
PACKAGE_NAME=${TITLE}
PYTHONTOOLDIR=/tmp/relocatable-python
PAYLOAD=\
	pack-plugin\
	pack-script-postinstall\
	pack-Library-LaunchDaemons-com.grahamgilbert.crypt.plist \
	pack-checkin \
	pack-script-preinstall

#################################################

build: check_variables clean-crypt
	xcodebuild -project ../Crypt.xcodeproj -configuration Release

clean-crypt:
	rm -rf ../build
	@rm -rf Crypt.pkg

pack-plugin: build
	@sudo ${RM} -rf ${WORK_D}
	@sudo mkdir -p ${WORK_D}/Library/Security/SecurityAgentPlugins
	@sudo ${CP} -R ../build/Release/Crypt.bundle ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle
	@sudo codesign --force --deep -s "${DEV_APP_CERT}" ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle/Contents/Frameworks/*
	@sudo codesign --force --deep -s "${DEV_APP_CERT}" ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle/Contents/MacOS/*

pack-checkin: clean-python build-python l_Library
	@sudo mkdir -p ${WORK_D}/Library/Crypt
	@sudo ${CP} checkin ${WORK_D}/Library/Crypt/checkin
	@sudo ${CP} -R Python.framework ${WORK_D}/Library/Crypt/Python.framework
	@sudo /bin/ln -s /Library/Crypt/Python.framework/Versions/3.8/bin/python3 ${WORK_D}/Library/Crypt/python
	@sudo chown -R root:wheel ${WORK_D}/Library/Crypt
	@sudo chmod 755 ${WORK_D}/Library/Crypt/checkin

dist: pkg
	@sudo rm -f Distribution
	python generate_dist.py
	@sudo productbuild --distribution Distribution Crypt-${BUNDLE_VERSION}.pkg
	@sudo rm -f Crypt.pkg
	@sudo rm -f Distribution

notarize:
	@./notarize.sh "${APPLE_ACC_USER}" "${APPLE_ACC_PWD}"

clean-python:
	@rm -rf Python.framework
	@rm -rf ${WORK_D}/Library/Crypt/Python.framework
	@rm -rf entitlements.plist

build-python:
	# Why not just run the make_relocatable_python.py here?
	# It can't find the temp folder that the python pkg is expanded into
	# if issued directly from Make, so we're currently shelling out until
	# we grok the GNU better. PS THANKS SHEA
	@rm -rf "${PYTHONTOOLDIR}"
	@git clone https://github.com/gregneagle/relocatable-python.git "${PYTHONTOOLDIR}"
	@./build_python_framework.sh "${DEV_APP_CERT}"

check_variables:
ifndef DEV_INSTALL_CERT
$(error "DEV_INSTALL_CERT" is not set)
endif
ifndef DEV_APP_CERT
$(error "DEV_APP_CERT" is not set)
endif
ifndef APPLE_ACC_USER
$(error "APPLE_ACC_USER" is not set)
endif
ifndef APPLE_ACC_PWD
$(error "APPLE_ACC_PWD" is not set)
endif
