use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr32BE;
use hex;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{rng, RngCore};
use sha2::Sha256;

pub type Aes256Ctr = Ctr32BE<Aes256>;
pub type HmacSha256 = Hmac<Sha256>;


pub fn decrypt_data(encrypted_data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<(), String> {
    let iv_array: [u8; 16] = iv.try_into().map_err(|_| "IV has an incorrect length (16 bytes expected)".to_string())?;

    let mut cipher = Aes256Ctr::new(key.into(), &iv_array.into());
    cipher.apply_keystream(encrypted_data);
    Ok(())
}

pub fn calculate_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|e| format!("Cannot create HMAC : {}", e))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn derive_key_from_master(
    master_key: &[u8],
    user_id: &str,
    iterations: u32,
    output_key_length: usize,
) -> Result<Vec<u8>, String> {
    let mut derived_key = vec![0u8; output_key_length];
    let salt = user_id.as_bytes();

    pbkdf2_hmac::<Sha256>(master_key, salt, iterations, &mut derived_key);

    Ok(derived_key)
}


pub fn initialize_file_cipher(key: &[u8]) -> Result<(String, Aes256Ctr), String> {
    let mut iv_bytes = [0u8; 16];
    rng().fill_bytes(&mut iv_bytes);
    let iv_hex = hex::encode(&iv_bytes);

    let cipher = Aes256Ctr::new(key.into(), &iv_bytes.into());
    Ok((iv_hex, cipher))
}

pub fn encrypt_chunk_in_stream(cipher: &mut Aes256Ctr, data: &mut [u8]) -> Vec<u8> {
    cipher.apply_keystream(data);
    data.to_vec()
}

pub fn decrypt_chunk_in_stream(cipher: &mut Aes256Ctr, encrypted_data: &mut [u8]) {
    cipher.apply_keystream(encrypted_data);
}