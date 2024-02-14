#!/usr/bin/env bash

mkdir -p build

APP_NAME="checkin"

cp $(bazel cquery --output=files //cmd:crypt-amd 2>/dev/null) build/${APP_NAME}.amd64

cp $(bazel cquery --output=files //cmd:crypt-arm 2>/dev/null) build/${APP_NAME}.arm64