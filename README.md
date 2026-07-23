# unegg

[![crates.io](https://img.shields.io/crates/v/unegg.svg)](https://crates.io/crates/unegg)
[![docs.rs](https://img.shields.io/docsrs/unegg)](https://docs.rs/unegg)
[![CI](https://github.com/alkegi/unegg/actions/workflows/ci.yml/badge.svg)](https://github.com/alkegi/unegg/actions/workflows/ci.yml)

EGG archive extractor written in Rust.

## Usage

```
unegg archive.egg                 # extract all files
unegg archive.egg file.txt        # extract specific file
unegg -d output/ archive.egg      # extract to directory
unegg --pwd SECRET archive.egg    # extract encrypted archive
unegg -l archive.egg              # list contents
unegg -p archive.egg file.txt     # extract to stdout
cat archive.egg | unegg -l -      # read from stdin
```

## Supported Features

### Compression
- Store (no compression)
- Deflate
- Bzip2
- LZMA
- AZO

### Encryption
- ZipCrypto (32-bit variant)
- AES-128 / AES-256 (CTR mode, PBKDF2-HMAC-SHA1)
- LEA-128 / LEA-256 (CTR mode, PBKDF2-HMAC-SHA1)

### Archive types
- Solid archives (continuous compressed stream across files)
- Split (multi-volume) archives (automatic volume discovery)
