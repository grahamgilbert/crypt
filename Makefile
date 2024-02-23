include /usr/local/share/luggage/luggage.make
include config.mk
USE_PKGBUILD=1
PB_EXTRA_ARGS+= --info "./Package/PackageInfo" --sign "${DEV_INSTALL_CERT}"
TITLE=Crypt
GITVERSION=$(shell ./Package/build_no.sh)
BUNDLE_VERSION=$(shell /usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "Crypt/Info.plist")
PACKAGE_VERSION=${BUNDLE_VERSION}.${GITVERSION}
CLANG_DIR := /opt/homebrew/opt/llvm/bin
REVERSE_DOMAIN=com.grahamgilbert
PACKAGE_NAME=${TITLE}
PAYLOAD=\
	pack-plugin\
	pack-checkin \
	pack-scripts \
	remove-xattrs

.PHONY: coverage

#################################################
## Why is all the bazel stuff commented out? It seems to have issues with Cgo.
gazelle:
	bazel run //:gazelle

run:
	# bazel run --platforms=@io_bazel_rules_go//go/toolchain:darwin_amd64 -- //cmd:crypt-arm64
	go run cmd/main.go

update-repos:
	bazel run //:gazelle-update-repos -- -from_file=go.mod

test:
	# bazel test --test_output=errors //...
	go test -v ./...

coverage:
	./tools/coverage.sh

build: check_variables clean-crypt build_binary
	xcodebuild -project Crypt.xcodeproj -configuration Release

clean-crypt:
	@sudo rm -rf build
	@sudo rm -rf Crypt.pkg

pack-plugin: build l_private_etc
	@sudo ${RM} -rf ${WORK_D}
	@sudo mkdir -p ${WORK_D}/private/etc/newsyslog.d
	@sudo ${CP} Package/newsyslog.d/crypt.conf ${WORK_D}/private/etc/newsyslog.d/crypt.conf
	@sudo mkdir -p ${WORK_D}/Library/Security/SecurityAgentPlugins
	@sudo ${CP} -R build/Release/Crypt.bundle ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle
	@sudo codesign --timestamp --force --deep -s "${DEV_APP_CERT}" ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle/Contents/Frameworks/*
	@sudo codesign --timestamp --force --deep -s "${DEV_APP_CERT}" ${WORK_D}/Library/Security/SecurityAgentPlugins/Crypt.bundle/Contents/MacOS/*

pack-scripts:
	@sudo ${INSTALL} -o root -g wheel -m 755 Package/postinstall ${SCRIPT_D}
	@sudo ${INSTALL} -o root -g wheel -m 755 Package/preinstall ${SCRIPT_D}

build_binary:
	# bazel build --platforms=@io_bazel_rules_go//go/toolchain:darwin_amd64 //:cmd:crypt-amd
	# bazel build --platforms=@io_bazel_rules_go//go/toolchain:darwin_arm //cmd:crypt-arm
	# tools/bazel_to_builddir.sh
	CGO_ENABLED=1 CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++ GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=${PACKAGE_VERSION}" -o build/checkin.arm64 cmd/main.go
	CGO_ENABLED=1 CC=/opt/homebrew/opt/llvm/bin/clang CXX=/opt/homebrew/opt/llvm/bin/clang++ GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=${PACKAGE_VERSION}" -o build/checkin.amd64 cmd/main.go
	/usr/bin/lipo -create -output build/checkin build/checkin.arm64 build/checkin.amd64
	/bin/rm build/checkin.arm64
	/bin/rm build/checkin.amd64
	@sudo chown root:wheel build/checkin
	@sudo chmod 755 build/checkin
	

sign_binary:
	@sudo codesign --timestamp --force --deep -s "${DEV_APP_CERT}" build/checkin

pack-checkin: l_Library l_Library_LaunchDaemons build_binary sign_binary
	@sudo mkdir -p ${WORK_D}/Library/Crypt
	@sudo ${CP} build/checkin ${WORK_D}/Library/Crypt/checkin
	@sudo chown -R root:wheel ${WORK_D}/Library/Crypt
	@sudo chmod 755 ${WORK_D}/Library/Crypt/checkin
	@sudo ${INSTALL} -m 644 -g wheel -o root Package/com.grahamgilbert.crypt.plist ${WORK_D}/Library/LaunchDaemons

dist: pkg
	@sudo rm -f Distribution
	python3 generate_dist.py
	@sudo productbuild --distribution Distribution Crypt-${BUNDLE_VERSION}.pkg
	@sudo rm -f Crypt.pkg
	@sudo rm -f Distribution

notarize:
	@./notarize.sh "${APPLE_ACC_USER}" "${APPLE_ACC_PWD}" "./Crypt.pkg"

remove-xattrs:
	@sudo xattr -rd com.dropbox.attributes ${WORK_D}
	@sudo xattr -rd com.dropbox.internal ${WORK_D}
	@sudo xattr -rd com.apple.ResourceFork ${WORK_D}
	@sudo xattr -rd com.apple.FinderInfo ${WORK_D}
	@sudo xattr -rd com.apple.metadata:_kMDItemUserTags ${WORK_D}
	@sudo xattr -rd com.apple.metadata:kMDItemFinderComment ${WORK_D}
	@sudo xattr -rd com.apple.metadata:kMDItemOMUserTagTime ${WORK_D}
	@sudo xattr -rd com.apple.metadata:kMDItemOMUserTags ${WORK_D}
	@sudo xattr -rd com.apple.metadata:kMDItemStarRating ${WORK_D}
	@sudo xattr -rd com.dropbox.ignored ${WORK_D}

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
ifeq ("$(wildcard $(CLANG_DIR))","")
$(error The directory $(CLANG_DIR) does not exist)
endif