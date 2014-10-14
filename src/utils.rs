use std::num::FromStrRadix;

pub fn hash_str_to_vec(s: &str) -> Vec<u8> {
    let mut res = Vec::new();
    assert!(s.len() % 2 == 0, "Hash str should have len = 2 * n");
    for i in range(0, s.len() / 2) {
        let substr = s.slice(i * 2, (i + 1) * 2);
        let t: Option<u8> = FromStrRadix::from_str_radix(substr, 16);
        assert!(t.is_some(), "Hash str must contain only hex digits, i.e. [0-9a-f]");
        res.push(t.unwrap());
    }

    res
}

#[test]
fn test_hash_str_to_vec() {
    let hash_str = "6204f6617e1af7495394250655f43600cd483e2dfc2005e92d0fe439d0723c34";
    let correct_vec = vec![0x62, 0x04, 0xf6, 0x61, 0x7e, 0x1a, 0xf7, 0x49,
                           0x53, 0x94, 0x25, 0x06, 0x55, 0xf4, 0x36, 0x00,
                           0xcd, 0x48, 0x3e, 0x2d, 0xfc, 0x20, 0x05, 0xe9,
                           0x2d, 0x0f, 0xe4, 0x39, 0xd0, 0x72, 0x3c, 0x34];

    assert_eq!(correct_vec, hash_str_to_vec(hash_str));
}
