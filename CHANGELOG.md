# Changelog

## [v4.1.0](https://github.com/grahamgilbert/crypt/compare/4.0.0...4.1.0)

Crupt 4.1.0 only supports macOS 11 and up. Older versions are not supported.

### Fixed in this release

- Preinstall script failed if FoundationPlist.pyc didn't exist #105
- `get_os_version` now works on macOS 12 #107 @discentem

### Enhancements

- All of Crypt is now distributed as Universal2 (No Rosetta required!)
- Python is updated to 3.9.X

## [v4.0.0](https://github.com/grahamgilbert/crypt/compare/3.3.1...4.0.0)

Changes are lost in the mists of time.

## [v3.3.1](https://github.com/grahamgilbert/crypt/compare/3.3.0...3.3.1)

### Fixed in this release

- On Catalina, skip local checking of `usingrecoverykey` after using recovery key to prevent lockout of changing user password (#99 @weswhet)

### Enhancements

- Added documentation on `AdditionalCurlOpts` (#97, #98 @asyiu)
- Example PPPC/TCC profile (@grahamgilbert)
- Document `curl` POST in `checkin` script and use long-form arguments (#93 @erikng)

## [v3.3.0](https://github.com/grahamgilbert/crypt/compare/3.2.1...3.3.0)

### Fixed in this release

- Secrets are no longer visible when inspecting the process (#88 @bdemetris)
- Cleanup the working directory prior to build (#90 @clburlison)

### Enhancements

- Updated to Swift 4.2 (#91 @clburlison)
