//! Mihomo-compatible age provider decryption.
//!
//! Upstream Mihomo accepts classic X25519 age identities and its
//! `AGE-SECRET-KEY-PQ-` ML-KEM-768/X25519 hybrid identity. The Rust `age`
//! crate implements the former; the small identity adapter below implements
//! Mihomo's HPKE stanza with the standard X-Wing KEM from `hpke`.

use std::{io::Read, str::FromStr};

use ::age as age_crate;
use age_core::format::{FILE_KEY_BYTES, FileKey, Stanza};
use age_crate::{Decryptor, Identity, armor::ArmoredReader, x25519};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::XWing,
    setup_receiver,
};
use thiserror::Error;

pub const AGE_ARMOR_HEADER: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";
const HYBRID_IDENTITY_HRP: &str = "age-secret-key-pq-";
const HYBRID_STANZA: &str = "mlkem768x25519";
const HYBRID_INFO: &[u8] = b"age-encryption.org/mlkem768x25519";

#[derive(Debug, Error)]
pub enum AgeError {
    #[error("age-secret-key 中没有可用的 X25519 或 ML-KEM-768/X25519 私钥")]
    NoIdentity,
    #[error("age 私钥无效: {0}")]
    InvalidIdentity(String),
    #[error("age 解密失败: {0}")]
    Decrypt(#[from] age_crate::DecryptError),
    #[error("读取 age 明文失败: {0}")]
    Io(#[from] std::io::Error),
}

/// Decrypt an armored provider payload. Like Mihomo, plaintext input is
/// returned unchanged even when `age-secret-key` is configured.
pub fn decrypt_provider_payload(raw: &[u8], secret_keys: &str) -> Result<Vec<u8>, AgeError> {
    if !raw.starts_with(AGE_ARMOR_HEADER) {
        return Ok(raw.to_vec());
    }

    let identities = parse_identities(secret_keys)?;
    let armored = ArmoredReader::new(raw);
    let decryptor = Decryptor::new(armored)?;
    let mut plaintext = decryptor.decrypt(identities.iter().map(|identity| identity.as_ref()))?;
    let mut output = Vec::new();
    plaintext.read_to_end(&mut output)?;
    Ok(output)
}

fn parse_identities(value: &str) -> Result<Vec<Box<dyn Identity>>, AgeError> {
    let mut identities: Vec<Box<dyn Identity>> = Vec::new();
    for line in value.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line
            .get(..HYBRID_IDENTITY_HRP.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(HYBRID_IDENTITY_HRP))
        {
            identities.push(Box::new(HybridIdentity::from_str(line)?));
        } else {
            let identity = x25519::Identity::from_str(line)
                .map_err(|error| AgeError::InvalidIdentity(error.to_string()))?;
            identities.push(Box::new(identity));
        }
    }
    if identities.is_empty() {
        return Err(AgeError::NoIdentity);
    }
    Ok(identities)
}

struct HybridIdentity {
    private_key: <XWing as KemTrait>::PrivateKey,
}

impl FromStr for HybridIdentity {
    type Err = AgeError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        let (hrp, key) = bech32::decode(encoded)
            .map_err(|error| AgeError::InvalidIdentity(error.to_string()))?;
        if !hrp.as_str().eq_ignore_ascii_case(HYBRID_IDENTITY_HRP) {
            return Err(AgeError::InvalidIdentity(format!(
                "不支持的混合密钥 HRP `{hrp}`"
            )));
        }
        let private_key = <XWing as KemTrait>::PrivateKey::from_bytes(&key).map_err(|error| {
            AgeError::InvalidIdentity(format!("ML-KEM-768/X25519 私钥长度或编码无效: {error:?}"))
        })?;
        Ok(Self { private_key })
    }
}

impl Identity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age_crate::DecryptError>> {
        if stanza.tag != HYBRID_STANZA {
            return None;
        }
        if stanza.args.len() != 1 || stanza.body.len() != FILE_KEY_BYTES + 16 {
            return Some(Err(age_crate::DecryptError::InvalidHeader));
        }
        let encapsulated = STANDARD_NO_PAD
            .decode(&stanza.args[0])
            .or_else(|_| STANDARD.decode(&stanza.args[0]))
            .ok()
            .and_then(|bytes| <XWing as KemTrait>::EncappedKey::from_bytes(&bytes).ok());
        let Some(encapsulated) = encapsulated else {
            return Some(Err(age_crate::DecryptError::InvalidHeader));
        };
        let mut context = match setup_receiver::<ChaCha20Poly1305, HkdfSha256, XWing>(
            &OpModeR::Base,
            &self.private_key,
            &encapsulated,
            HYBRID_INFO,
        ) {
            Ok(context) => context,
            Err(_) => return None,
        };
        context.open(&stanza.body, b"").ok().and_then(|plaintext| {
            let file_key: [u8; FILE_KEY_BYTES] = plaintext.try_into().ok()?;
            Some(Ok(FileKey::new(Box::new(file_key))))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ::age::{
        Encryptor,
        armor::{ArmoredWriter, Format},
        secrecy::ExposeSecret,
    };
    use hpke::{OpModeS, Serializable, setup_sender_with_rng};

    use super::*;

    #[test]
    fn plaintext_is_not_modified() {
        let raw = b"proxies: []";
        assert_eq!(
            decrypt_provider_payload(raw, "not parsed for plaintext").unwrap(),
            raw
        );
    }

    #[test]
    fn decrypts_x25519_ascii_armor() {
        let identity = x25519::Identity::generate();
        let recipient = identity.to_public();
        let mut armored = Vec::new();
        {
            let armor = ArmoredWriter::wrap_output(&mut armored, Format::AsciiArmor).unwrap();
            let mut encryptor =
                Encryptor::with_recipients(std::iter::once(&recipient as &dyn ::age::Recipient))
                    .unwrap()
                    .wrap_output(armor)
                    .unwrap();
            encryptor.write_all(b"proxies: []").unwrap();
            encryptor.finish().and_then(|armor| armor.finish()).unwrap();
        }

        let decrypted =
            decrypt_provider_payload(&armored, &identity.to_string().expose_secret()).unwrap();
        assert_eq!(decrypted, b"proxies: []");
    }

    #[test]
    fn unwraps_mihomo_mlkem768x25519_stanza() {
        let mut rng = rand::rng();
        let (private_key, public_key) = XWing::gen_keypair_with_rng(&mut rng);
        let identity = HybridIdentity { private_key };
        let (encapsulated, mut context) = setup_sender_with_rng::<
            ChaCha20Poly1305,
            HkdfSha256,
            XWing,
        >(
            &OpModeS::Base, &public_key, HYBRID_INFO, &mut rng
        )
        .unwrap();
        let expected = [0x5a; FILE_KEY_BYTES];
        let body = context.seal(&expected, b"").unwrap();
        let stanza = Stanza {
            tag: HYBRID_STANZA.into(),
            args: vec![STANDARD_NO_PAD.encode(encapsulated.to_bytes())],
            body,
        };

        let file_key = identity.unwrap_stanza(&stanza).unwrap().unwrap();
        assert_eq!(file_key.expose_secret(), &expected);
    }
}
