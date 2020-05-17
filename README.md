gauth: replace Google Authenticator
===================================

/*
What: Google Auth for win7
Edits: moshahmed@gmail 2019
Repo: https://github.com/moshahmed/gauth
Forked: https://github.com/pcarrier/gauth 
Usage:
> go get github.com/pcarrier
> go get github.com/howeyc/gopass
> go build gauth.go
 
$ cd ~/.ssh
$ cat gauth.mfa
    test,ABC
# Encrypt gauth.mfa to gauth.ssl
$ openssl enc -aes-128-cbc -md sha256 -in gauth.mfa -out gauth.ssl
    password=xxx
# Decrypt gauth.ssl and edit gauth.mfa
$ openssl enc -aes-128-cbc -md sha256 -d -in gauth.ssl -out gauth.mfa
    password=xxx
# Get the 2fa code
$ go run gauth.go [tes] [$HOME/.ssh/gauth.ssl]
|   pass:xxx
|   2FA    Name
|   129079 test
# Print qrcode.txt on console as scanable image
  $ pip install qrcode
  $ qr "otpauth://totp/Example:mosh@mosh.com?secret=XYZ&issuer=SOMEONE"
    qrcode printed on Console.
# Convert text to png image, from https://github.com/miyako/console-qrencode
  $ waqrencode -t png -i mfa.txt -o mfa.png
# Convert qrcode.jpg image to string
  $ zbarimg qrcode.jpg
*/

- Remember to keep your system clock synchronized

Encryption
----------

`gauth` supports password-based encryption of `gauth.csv`. To encrypt, use:

        $ openssl enc -aes-128-cbc -md sha256 -in gauth.csv -out ~/.config/gauth.csv
        enter aes-128-cbc encryption password:
        Verifying - enter aes-128-cbc encryption password:

`gauth` will then prompt you for that password on every run:

        $ gauth
        Encryption password: 
                   prev   curr   next
        LastPass   915200 479333 408710

Note that this encryption mechanism is far from ideal from a pure security standpoint.
Please read [OpenSSL's notes on the subject](http://www.openssl.org/docs/crypto/EVP_BytesToKey.html#NOTES).

Compatibility
-------------

Tested with:

- Airbnb
- Apple
- AWS
- DreamHost
- Dropbox
- Evernote
- Facebook
- Gandi
- Github
- Google
- LastPass
- Linode
- Microsoft
- Okta (reported by Bryan Baldwin)
- WP.com
- bittrex.com
- poloniex.com

Please report further results to pierre@gcarrier.fr.

Rooted Android?
---------------

If your Android phone is rooted, it's easy to "back up" your secrets from an `adb shell` into `gauth`.

    # sqlite3 /data/data/com.google.android.apps.authenticator2/databases/database \
              'select email,secret from accounts'

Really, does this make sense?
-----------------------------

At least to me, it does. My laptop features encrypted storage, a stronger authentication mechanism,
and I take good care of its physical integrity.

My phone also runs arbitrary apps, is constantly connected to the Internet, gets forgotten on tables.

Thanks to the convenience of a command line utility, my usage of 2-factor authentication went from
3 to 10 services over a few days.

Clearly a win for security.
