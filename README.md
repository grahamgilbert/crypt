# Crypt 2

**WARNING:** As this has the potential for stopping users from logging in, extensive testing should take place before deploying into production.

Crypt 2 is an authorization plugin that will enforce FileVault 2, and then submit it to an instance of [Crypt Server](https://github.com/grahamgilbert/crypt-server). It makes use of Swift, so is theoretically compatible with 10.9 +, however in it's present alpha quality state, it has only been tested on 10.11.

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

## Credits

Crypt 2 couldn't have been written without the help of [Tom Burgin](https://github.com/tburgin) - he is responsible for all of the good code in this project. The bad bits are mine.
