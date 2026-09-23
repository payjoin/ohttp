# Changelog
All notable changes to the crates in this repository will be documented in this file. Entries are for `bitcoin-ohttp` unless they name another crate.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-09-23

### Changes

* HKDF is now computed over rust-bitcoin's [`bitcoin_hashes`](https://crates.io/crates/bitcoin_hashes) HMAC instead of the [`hkdf`](https://crates.io/crates/hkdf) and [`sha2`](https://crates.io/crates/sha2) crates. `bitcoin_hashes` 0.14 ships HMAC but not HKDF, so RFC 5869 Extract and Expand are implemented in this crate
* ChaCha20-Poly1305 is now backed by rust-bitcoin's [`chacha20-poly1305`](https://crates.io/crates/chacha20-poly1305) instead of [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305). Ciphertexts are unchanged
* Dropped the `aead`, `aes-gcm`, `chacha20poly1305`, `hkdf` and `sha2` dependencies
* Depend on [`bitcoin-hpke`](https://crates.io/crates/bitcoin-hpke) 0.20.0, which moves the HPKE half of this crate onto rust-bitcoin's SHA-256 and ChaCha20-Poly1305 as well
* `Error::Aead` no longer wraps an `aead::Error` and is now a unit variant
* `ClientRequest::from_config` takes `&KeyConfig` instead of `&mut KeyConfig`. Callers passing `&mut` still compile
* `KeyConfig::decode` returns `Error::Unsupported` when no symmetric suite is left after pruning unsupported ones. `KeyConfig::decode_list` skips such configs
* `PrivateKey`'s `Debug` impl no longer prints key material
* Bumped MSRV from 1.63.0 to 1.85.0 and moved to edition 2024
* `bhttp`: removed the `Error::ChunkTooLarge` variant, which was gated on a `stream` feature the crate never declares and stopped the workspace compiling on current rustc. `bhttp` stays at 0.5.3

### Fixes

* `KeyConfig` no longer advertises the AES-128-GCM and AES-256-GCM suites. `bitcoin-hpke` only implements ChaCha20-Poly1305, so a peer that selected AES-GCM got `Error::InvalidKeyType`. Configs from other peers that list AES-GCM still parse, with those suites pruned

## [0.6.0] - 2024-09-04

First release as `bitcoin-ohttp`, forked from [martinthomson/ohttp](https://github.com/martinthomson/ohttp) onto `bitcoin-hpke`. See the git history up to the `bitcoin-ohttp-0.6.0` tag for details.
