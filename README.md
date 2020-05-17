gauth: replace Google Authenticator
===================================
```
What: Google Auth for win7
Edits: moshahmed@gmail 2019
Repo: https://github.com/moshahmed/gauth
Forked: https://github.com/pcarrier/gauth 
Usage:
# Original source github.com/pcarrier
> go get github.com/moshahmed/gauth
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
```
