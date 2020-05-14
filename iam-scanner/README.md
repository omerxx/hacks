# IAM Scanner
Scans AWS IAM users for unused or old keys and passwords. Cleans up on demand according to a set of rules.
It uses existing AWS CLI profiles on the local environment. If non are provided it uses `default`.

### Rules
* Rules:
* [\*] If a user on an account never used login - disable his console access
* [\*] If a key has never been used - remove it
* [\*] If a key hasn’t been used in over a year - remove it
* [not implemented] If a user has never accessed the console and hasn’t got keys (or has unused keys), delete the user

### Installation
Grab the binary from releases

### Usage
```bash
# Dry run on multiple profiles
iamscanner -profiles staging,production

# Active
iamscanner -profiles staging -active
```

### Build from source
```bash
go build -o iamscanner
```
