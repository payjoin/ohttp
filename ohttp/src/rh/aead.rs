#![allow(dead_code)] // TODO: remove

use std::convert::TryFrom;

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

use super::SymKey;
use crate::{
    err::{Error, Res},
    hpke::Aead as AeadId,
};

/// All the nonces are the same length.  Exploit that.
pub const NONCE_LEN: usize = 12;
const COUNTER_LEN: usize = 8;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

type SequenceNumber = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
}

/// ChaCha20-Poly1305, the only AEAD this crate implements. `bitcoin-hpke` dropped
/// the AES-GCM schemes in 0.13.0, so the GCM suites were never usable end to end.
pub struct Aead {
    mode: Mode,
    key: [u8; KEY_LEN],
    nonce_base: [u8; NONCE_LEN],
    seq: SequenceNumber,
}

impl Aead {
    pub fn new(
        mode: Mode,
        algorithm: AeadId,
        key: &SymKey,
        nonce_base: [u8; NONCE_LEN],
    ) -> Res<Self> {
        if algorithm != AeadId::ChaCha20Poly1305 {
            return Err(Error::Unsupported);
        }
        let key = <[u8; KEY_LEN]>::try_from(key.as_ref()).map_err(|_| Error::Unsupported)?;
        Ok(Self {
            mode,
            key,
            nonce_base,
            seq: 0,
        })
    }

    #[cfg(test)]
    #[allow(clippy::unnecessary_wraps)]
    fn import_key(_alg: AeadId, k: &[u8]) -> Res<SymKey> {
        Ok(SymKey::from(k))
    }

    fn nonce(&self, seq: SequenceNumber) -> [u8; NONCE_LEN] {
        let mut nonce = self.nonce_base;
        for (i, n) in nonce.iter_mut().rev().take(COUNTER_LEN).enumerate() {
            *n ^= u8::try_from((seq >> (8 * i)) & 0xff).unwrap();
        }
        nonce
    }

    fn cipher(&self, nonce: [u8; NONCE_LEN]) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::new(self.key), Nonce::new(nonce))
    }

    #[allow(clippy::unnecessary_wraps)] // Res is part of the interface shared with the NSS backend
    pub fn seal(&mut self, aad: &[u8], pt: &[u8]) -> Res<Vec<u8>> {
        assert_eq!(self.mode, Mode::Encrypt);
        let nonce = self.nonce(self.seq);
        self.seq += 1;
        let mut ct = pt.to_vec();
        let tag = self.cipher(nonce).encrypt(&mut ct, Some(aad));
        ct.extend_from_slice(&tag);
        Ok(ct)
    }

    pub fn open(&mut self, aad: &[u8], seq: SequenceNumber, ct: &[u8]) -> Res<Vec<u8>> {
        assert_eq!(self.mode, Mode::Decrypt);
        if ct.len() < TAG_LEN {
            return Err(Error::Truncated);
        }
        let (body, tag) = ct.split_at(ct.len() - TAG_LEN);
        let tag = <[u8; TAG_LEN]>::try_from(tag).map_err(|_| Error::Truncated)?;
        let nonce = self.nonce(seq);
        let mut pt = body.to_vec();
        self.cipher(nonce)
            .decrypt(&mut pt, tag, Some(aad))
            .map_err(|_| Error::Aead)?;
        Ok(pt)
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::super::{hpke::Aead as AeadId, init},
        Aead, Mode, NONCE_LEN, SequenceNumber,
    };

    /// Check that the first invocation of encryption matches expected values.
    /// Also check decryption of the same.
    fn check0(
        algorithm: AeadId,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        pt: &[u8],
        ct: &[u8],
    ) {
        init();
        let k = Aead::import_key(algorithm, key).unwrap();

        let mut enc = Aead::new(Mode::Encrypt, algorithm, &k, *nonce).unwrap();
        let ciphertext = enc.seal(aad, pt).unwrap();
        assert_eq!(&ciphertext[..], ct);

        let mut dec = Aead::new(Mode::Decrypt, algorithm, &k, *nonce).unwrap();
        let plaintext = dec.open(aad, 0, ct).unwrap();
        assert_eq!(&plaintext[..], pt);
    }

    fn decrypt(
        algorithm: AeadId,
        key: &[u8],
        nonce: &[u8; NONCE_LEN],
        seq: SequenceNumber,
        aad: &[u8],
        pt: &[u8],
        ct: &[u8],
    ) {
        let k = Aead::import_key(algorithm, key).unwrap();
        let mut dec = Aead::new(Mode::Decrypt, algorithm, &k, *nonce).unwrap();
        let plaintext = dec.open(aad, seq, ct).unwrap();
        assert_eq!(&plaintext[..], pt);
    }

    /// The QUIC ChaCha20-Poly1305 sample (RFC 9001 A.5). Pins the AEAD to a published
    /// vector so a cipher swap cannot silently change the wire format.
    #[test]
    fn quic_chacha() {
        const ALG: AeadId = AeadId::ChaCha20Poly1305;
        const KEY: &[u8] = &[
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c,
            0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79,
            0xfb, 0x23, 0xe1, 0xc8,
        ];
        const NONCE_BASE: &[u8; NONCE_LEN] = &[
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ];
        // Note that this integrates the sequence number of 654360564 from the example,
        // otherwise we can't use a sequence number of 0 to encrypt.
        const NONCE: &[u8; NONCE_LEN] = &[
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0,
        ];
        const AAD: &[u8] = &[0x42, 0x00, 0xbf, 0xf4];
        const PT: &[u8] = &[0x01];
        const CT: &[u8] = &[
            0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2,
            0x5a, 0x5b, 0xfb,
        ];
        check0(ALG, KEY, NONCE, AAD, PT, CT);
        // Now use the real nonce and sequence number from the example.
        decrypt(ALG, KEY, NONCE_BASE, 654_360_564, AAD, PT, CT);
    }

    /// The AES-GCM suites were never implementable here, so construction must fail
    /// cleanly rather than half-work.
    #[test]
    fn aes_gcm_unsupported() {
        init();
        let k = Aead::import_key(AeadId::ChaCha20Poly1305, &[0; 32]).unwrap();
        assert!(Aead::new(Mode::Encrypt, AeadId::Aes128Gcm, &k, [0; NONCE_LEN]).is_err());
        assert!(Aead::new(Mode::Encrypt, AeadId::Aes256Gcm, &k, [0; NONCE_LEN]).is_err());
    }
}
