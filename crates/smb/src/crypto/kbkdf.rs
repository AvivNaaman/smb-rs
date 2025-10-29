use aes::cipher::{InvalidLength, typenum};
use ccm::KeyInit;
use hmac::{Hmac, Mac};
use rust_kbkdf::{
    CounterMode, InputType, KDFMode, PseudoRandomFunction, PseudoRandomFunctionKey, SpecifiedInput,
    kbkdf,
};
use sha2::Sha256;

use super::CryptoError;
type HmacSha256 = Hmac<Sha256>;

/// The type of derived keys for SMB2, outputting from kbkdf.
pub type DerivedKey = [u8; 16];
pub type KeyToDerive = [u8; 16];

/// Key-based key derivation function using HMAC-SHA256.
/// SP108-800-CTR-HMAC-SHA256; L*8 bits; 32-bit counter.
///
/// # Arguments
/// * `L` - The length of the output key, IN BYTES.
pub fn kbkdf_hmacsha256<const L: usize>(
    key: &KeyToDerive,
    label: &[u8],
    context: &[u8],
) -> Result<[u8; L], CryptoError> {
    assert!(L % 8 == 0);

    let key = HmacSha256KeyHandle { key: *key };

    let mut prf = HmacSha256Prf::default();
    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });

    let input = InputType::SpecifiedInput(SpecifiedInput { label, context });

    let mut output = [0; L];
    kbkdf(&mode, &input, &key, &mut prf, &mut output)?;

    Ok(output)
}

struct HmacSha256KeyHandle {
    key: KeyToDerive,
}

impl PseudoRandomFunctionKey for HmacSha256KeyHandle {
    type KeyHandle = KeyToDerive;

    fn key_handle(&self) -> &Self::KeyHandle {
        &self.key
    }
}

#[derive(Default)]
struct HmacSha256Prf {
    hmac: Option<HmacSha256>,
}

impl PseudoRandomFunction<'_> for HmacSha256Prf {
    type KeyHandle = KeyToDerive;

    type PrfOutputSize = typenum::U32;

    type Error = InvalidLength;

    fn init(
        &mut self,
        key: &'_ dyn PseudoRandomFunctionKey<KeyHandle = Self::KeyHandle>,
    ) -> Result<(), Self::Error> {
        assert!(self.hmac.is_none());
        self.hmac = Some(HmacSha256::new_from_slice(key.key_handle())?);
        Ok(())
    }

    fn update(&mut self, msg: &[u8]) -> Result<(), Self::Error> {
        self.hmac.as_mut().unwrap().update(msg);
        Ok(())
    }

    fn finish(&mut self, out: &mut [u8]) -> Result<usize, Self::Error> {
        let result = self.hmac.take().unwrap().finalize().into_bytes();
        out.copy_from_slice(&result);
        Ok(result.len())
    }
}
