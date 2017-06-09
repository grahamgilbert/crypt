# Crypt 2

**WARNING:** As this has the potential for stopping users from logging in, extensive testing should take place before deploying into production.

Crypt 2 is an authorization plugin that will enforce FileVault 2, and then submit it to an instance of [Crypt Server](https://github.com/grahamgilbert/crypt-server). Crypt 2 has been tested against 10.11 and 10.12 - it should in theory work down to 10.9, but test throughly to ensure it works as expected.

## Features

* Uses native authorization plugin so FileVault enforcement cannot be skipped.
* Escrow is delayed until there is an active user, so FileVault can be enforced when the Mac is offline.
* Administrators can specify a series of username that should not have to enable FileVault (IT admin, for example).

## Configuration

Preferences can be set either in `/Library/Preferences/com.grahamgilbert.crypt.plist` or via MXC / Profiles.

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

As of version 2.2.0 Crypt2 can rotate the recovery key, if the key is used to unlock the disk. There is a small caveat that this feature only works if the key is still present on the disk. This is set to `TRUE` by default. NOTE: Future plan is to add this to the authorized plug-in so a key is not needed on disk.

``` bash
$ sudo defaults write /Library/Preferences/com.grahamgilbert.crypt RotateUsedKey -bool FALSE
```


## Uninstalling

The install package will modify the Authorization DB - you need to remove these entries before removing the Crypt Authorization Plugin. A script that will do this can be found at [Package/uninstall](https://github.com/grahamgilbert/crypt2/blob/master/Package/uninstall).

## Building from source

You will need to configure Xcode to sign the bundle before building. Instructions for this are out of the scope of this readme, and [are available on Apple's site](https://developer.apple.com/support/code-signing/).

* Install [The Luggage](https://github.com/unixorn/luggage)
* ``cd Package``
* ``make pkg``

## Credits

Crypt 2 couldn't have been written without the help of [Tom Burgin](https://github.com/tburgin) - he is responsible for all of the good code in this project. The bad bits are mine.
