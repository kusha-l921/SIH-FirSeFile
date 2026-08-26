const POLY: u32 = 0x82F6_3B78;

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

pub fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc = CRC_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_standard_check_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn empty_input_yields_zero() {
        assert_eq!(crc32c(b""), 0x0000_0000);
    }

    #[test]
    fn single_byte_vector_matches_reference() {
        assert_eq!(crc32c(b"a"), 0xC1D0_4330);
    }

    #[test]
    fn rfc3720_test_vectors_match() {
        assert_eq!(crc32c(&[0x00u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);

        let increasing: Vec<u8> = (0u8..32).collect();
        assert_eq!(crc32c(&increasing), 0x46DD_794E);

        let decreasing: Vec<u8> = (0u8..32).rev().collect();
        assert_eq!(crc32c(&decreasing), 0x113F_DB5C);
    }

    #[test]
    fn output_is_stable_across_calls() {
        let data = b"deterministic forensic metadata";
        let first = crc32c(data);
        assert_eq!(first, crc32c(data));
        assert_ne!(first, crc32c(b"deterministic forensic metadat"));
    }
}
