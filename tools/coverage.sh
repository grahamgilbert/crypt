#!/bin/sh
go install github.com/jandelgado/gcov2lcov
rm -rf coverage
mkdir -p coverage
# bazel coverage --combined_report=lcov //...
# mv $(BAZEL_OUTPUT_PATH)/_coverage/_coverage_report.dat coverage/lcov.info
go test -coverprofile=coverage/coverage.out ./...
go tool cover -func=coverage/coverage.out -o coverage/coverage.txt
gcov2lcov -infile=coverage/coverage.txt -outfile=coverage/lcov.info