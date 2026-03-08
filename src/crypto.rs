//! XOR encryption for dump output

/// Generate a random XOR key
pub fn generate_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    // Use rdtsc for simple entropy (not cryptographic)
    let mut seed: u64;
    unsafe {
        std::arch::asm!("rdtsc", out("eax") seed, out("edx") _);
    }
    for i in 0..len {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        key[i] = (seed >> 33) as u8;
    }
    key
}

/// XOR encrypt/decrypt data with a rolling key
pub fn xor_transform(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Encrypt dump data and prepend key length + key
pub fn encrypt_dump(data: &mut Vec<u8>) -> Vec<u8> {
    let key = generate_key(32);
    xor_transform(data, &key);

    // Prepend: key_len (4 bytes LE) + key + encrypted data
    let mut output = Vec::with_capacity(4 + key.len() + data.len());
    output.extend_from_slice(&(key.len() as u32).to_le_bytes());
    output.extend_from_slice(&key);
    output.extend_from_slice(data);
    output
}
