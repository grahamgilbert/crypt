#!/bin/sh

rm -rf coverage
mkdir -p coverage
# bazel coverage --combined_report=lcov //...
# mv $(BAZEL_OUTPUT_PATH)/_coverage/_coverage_report.dat coverage/lcov.info
go test -coverprofile=coverage/lcov.info ./...
