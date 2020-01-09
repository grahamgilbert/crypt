# Crypt

**WARNING:** As this has the potential for stopping users from logging in, extensive testing should take place before deploying into production.

Crypt is an authorization plugin that will enforce FileVault 2, and then submit it to an instance of [Crypt Server](https://github.com/grahamgilbert/crypt-server). Crypt has been tested against 10.13 and 10.14 - Crypt is believed to be functional on 10.12, but isn't extensively tested. For versions below 10.12 please use version 2 and below.

Version 3.0.0 now supports 10.12 and above, previous macOS version support has been deprecated!

When using Crypt with macOS 10.15 and higher, you will also need to deploy a PPC TCC profile via user approved MDM to allow Crypt to enable FileVault. [An example can be found here.](https://github.com/grahamgilbert/crypt/blob/master/ppctcc_example.mobileconfig)

## Features

* Uses native authorization plugin so FileVault enforcement cannot be skipped.
* Escrow is delayed until there is an active user, so FileVault can be enforced when the Mac is offline.
* Administrators can specify a series of username that should not have to enable FileVault (IT admin, for example).

#### New in v3.0.0
* Deprecated Support for before 10.12. Please use version 2.2.0.
* High Sierra Support.
* Added support for the use of Institutional Keys along with the default Personal Recovery Key. Just add your master keychain file at '/Library/Keychains/FileVaultMaster.keychain' and Crypt will handle the rest during initial Enablement.
* If the RotateUsedKey preference is True and RemovePlist is False and the file defined by OutputPath is missing from disk, a new Recovery key will be generated at login.
* OutputPath Preference. More info below.
* Local Recovery Key validation on 10.12.5+. More info below.
* Configurable Time Interval for re-escrowing (KeyEscrowInterval) the key if left on disk.

## Configuration

Preferences can be set either in `/Library/Preferences/com.grahamgilbert.crypt.plist` or via MCX / Profiles. An example profile can be found [here](https://github.com/grahamgilbert/crypt/blob/master/Example%20Crypt%20Profile.mobileconfig).

### ServerURL

The `ServerURL` preference sets your Crypt Server. Crypt will not enforce FileVault if this preference isn't set.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt ServerURL "https://crypt.example.com"
```

### SkipUsers

The `SkipUsers` preference allows you to define an array of users that will not be forced to enable FileVault.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt SkipUsers -array-add adminuser
```

### RemovePlist

By default, the plist with the FileVault Key will be removed once it has been escrowed. In a future version of Crypt, there will be the possibility of verifying the escrowed key with the client. In preparation for this feature, you can now choose to leave the key on disk.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt RemovePlist -bool FALSE
```

### RotateUsedKey

Crypt2 can rotate the recovery key, if the key is used to unlock the disk. There is a small caveat that this feature only works if the key is still present on the disk. This is set to `TRUE` by default.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt RotateUsedKey -bool FALSE
```

### ValidateKey

Crypt2 can validate the recovery key if it is stored on disk. If the key fails validation, the plist is removed so it can be regenerated on next login. This is set to `TRUE` by default.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt ValidateKey -bool FALSE
```

### OutputPath

As of version 3.0.0 you can now define a new location for where the recovery key is written to. Default for this is `'/var/root/crypt_output.plist'`.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt OutputPath "/path/to/different/location"
```

### KeyEscrowInterval

As of version 3.0.0 you can now define the time interval in Hours for how often Crypt tries to re-escrow the key, after the first successful escrow. Default for this is `1` hour.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt KeyEscrowInterval -int 2
```

### AdditionalCurlOpts

The `AdditionalCurlOpts` preference allows you to define an array of additional `curl` options to add to the `curl` command run during checkin to escrow the key to Crypt Server.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt AdditionalCurlOpts -array-add "--tlsv1.3"
```

### PostRunCommand

(Introduced in version 3.2.0) This is a command that is run after Crypt has detected an error condition with a stored key that cannot be resolved silently - either it has failed validation or the server has instructed the client to rotate the key. These cannot be resolved silently on APFS volumes, so the user will need to log in again. If you have a tool that can enforce a logout or a reboot, you can run it here. This preference can either be a string if your command has no spaces, or an array if there are spaces in the command.


## Uninstalling

The install package will modify the Authorization DB - you need to remove these entries before removing the Crypt Authorization Plugin. A script that will do this can be found at [Package/uninstall](https://github.com/grahamgilbert/crypt2/blob/master/Package/uninstall).

## Building from source

You will need to configure Xcode 9.3 (requires 10.13.2 or later) to sign the bundle before building. Instructions for this are out of the scope of this readme, and [are available on Apple's site](https://developer.apple.com/support/code-signing/).

* Install [The Luggage](https://github.com/unixorn/luggage)
* ``cd Package``
* ``make pkg``

## Credits

Crypt 2 couldn't have been written without the help of [Tom Burgin](https://github.com/tburgin) - he is responsible for all of the good code in this project. The bad bits are mine.
