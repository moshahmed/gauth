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
*/

package main

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
  "crypto/hmac"
  "crypto/sha1"
  "crypto/sha256"
  "encoding/base32"
  "encoding/csv"
  "fmt"
  "io/ioutil"
  "log"
  "math/big"
  "path"
  // "os/user"
  "os"
  "strings"
  // "syscall"
  "time"
  // "golang.org/x/crypto/ssh/terminal"
  "github.com/howeyc/gopass"
)

func TimeStamp() (int64, int) {
  time := time.Now().Unix()
  return time / 30, int(time % 30)
}

func normalizeSecret(sec string) string {
  noPadding := strings.ToUpper(strings.Replace(sec, " ", "", -1))
  padLength := 8 - (len(noPadding) % 8)
  if padLength < 8 {
    return noPadding + strings.Repeat("=", padLength)
  }
  return noPadding
}

func AuthCode(sec string, ts int64) (string, error) {
  key, err := base32.StdEncoding.DecodeString(sec)
  if err != nil {
    fmt.Fprintf(os.Stderr, "base32 Decode error %v",err)
    return "", err
  }
  enc := hmac.New(sha1.New, key)
  msg := make([]byte, 8, 8)
  msg[0] = (byte)(ts >> (7 * 8) & 0xff)
  msg[1] = (byte)(ts >> (6 * 8) & 0xff)
  msg[2] = (byte)(ts >> (5 * 8) & 0xff)
  msg[3] = (byte)(ts >> (4 * 8) & 0xff)
  msg[4] = (byte)(ts >> (3 * 8) & 0xff)
  msg[5] = (byte)(ts >> (2 * 8) & 0xff)
  msg[6] = (byte)(ts >> (1 * 8) & 0xff)
  msg[7] = (byte)(ts >> (0 * 8) & 0xff)
  if _, err := enc.Write(msg); err != nil {
    fmt.Fprintf(os.Stderr, "Write error %v",err)
    return "", err
  }
  hash := enc.Sum(nil)
  offset := hash[19] & 0x0f
  trunc := hash[offset : offset+4]
  trunc[0] &= 0x7F
  res := new(big.Int).Mod(new(big.Int).SetBytes(trunc), big.NewInt(1000000))
  return fmt.Sprintf("%06d", res), nil
}

func authCodeOrDie(sec string, ts int64) string {
  str, e := AuthCode(sec, ts)
  if e != nil {
    fmt.Fprintf(os.Stderr, "Invalid AuthCode %v",e)
    log.Fatal(e)
  }
  return str
}

func main() {
  filter := ""
  if len(os.Args) > 1 {
    filter = os.Args[1]
  }
  cfgPath := path.Join(os.Getenv("HOME"), ".ssh/gauth.ssl")
  if len(os.Args) > 2 {
    cfgPath = os.Args[2]
  }
  cfgContent, e := ioutil.ReadFile(cfgPath)
  if e != nil {
    fmt.Fprintf(os.Stderr, "error Readfile %s %v",cfgPath,e)
    log.Fatal(e)
  }

  // Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
  if bytes.Compare(cfgContent[:8], []byte{0x53, 0x61, 0x6c, 0x74, 0x65, 0x64, 0x5f, 0x5f}) == 0 {
    // fmt.Printf("password for %s:", cfgPath)
    fmt.Printf("pass:")
    // These dont work on windows, so use gopass.
    // passwd, e := terminal.ReadPassword(syscall.Stdin)
    // passwd, e := terminal.ReadPassword(0)
    // passwd, e := terminal.ReadPassword(int(syscall.Stdin))
    passwd, e := gopass.GetPasswd()
    if e != nil {
      fmt.Fprintf(os.Stderr, "GetPasswd error %v",e)
      log.Fatal(e)
    }
    // fmt.Printf("\n")
    salt := cfgContent[8:16]
    rest := cfgContent[16:]
    salting := sha256.New()
    salting.Write([]byte(passwd))
    salting.Write(salt)
    sum := salting.Sum(nil)
    key := sum[:16]
    iv := sum[16:]
    block, e := aes.NewCipher(key)
    if e != nil {
      fmt.Fprintf(os.Stderr, "aes.NewCipher error %v",e)
      log.Fatal(e)
    }

    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(rest, rest)
    // Remove padding
    i := len(rest)
    for i>0 && rest[i-1] < 16 {
      i--
    }
    cfgContent = rest[:i]
  }

  cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
  // Unix-style tabular
  cfgReader.Comma = ':'

  cfg, e := cfgReader.ReadAll()
  if e != nil {
    fmt.Fprintf(os.Stderr, "Read error %v",e)
    log.Fatal(e)
  }

  // currentTS, progress := TimeStamp()
  currentTS, _ := TimeStamp()
  // prevTS := currentTS - 1
  // nextTS := currentTS + 1

  // fmt.Printf("-- %10s %10s %10s %-20s\n", "prev", "curr", "next", "Name");
  fmt.Printf("| %6s |%-20s\n", "2FA", "Name");
  for _, record := range cfg {
    name := record[0]
    // fmt.Printf("name=%s\n", name);
    if (filter != "" && !strings.Contains(name, filter) ) {
      continue
    }
    secret := normalizeSecret(record[1])
    // fmt.Printf("secret=%s\n", secret);
    // prevToken := authCodeOrDie(secret, prevTS)
    // nextToken := authCodeOrDie(secret, nextTS)
    // fmt.Printf("%-2d %10s %10s %10s %-20s\n", 1+ii, prevToken, currentToken, nextToken, name)
    currentToken := authCodeOrDie(secret, currentTS)
    fmt.Printf("| %6s |%-20s\n", currentToken, name)
  }
  // fmt.Printf("[%-29s]\n", strings.Repeat("=", progress))
}
