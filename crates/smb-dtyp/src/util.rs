pub const fn parse_hex(c: u8) -> Result<u8, &'static str> {
    let c = match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return Err("Invalid hex character"),
    };
    Ok(c)
}

pub const fn parse_byte(b: &[u8], i: usize) -> Result<u8, &'static str> {
    let res = parse_hex(b[i]);
    let lower_byte = match res {
        Ok(val) => val,
        Err(e) => return Err(e),
    };
    let res = parse_hex(b[i + 1]);
    let upper_byte = match res {
        Ok(val) => val,
        Err(e) => return Err(e),
    };
    Ok((lower_byte << 4) | upper_byte)
}
