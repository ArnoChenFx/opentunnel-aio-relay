//! Minimal TLS ClientHello parser: extracts SNI and ALPN without
//! terminating TLS. Ported from `tls-client-hello.ts` in anomalyco/opentunnel.
//!
//! The relay reads only the ClientHello (up to 64 KiB) to route by SNI,
//! then forwards the raw encrypted bytes. It never sees plaintext.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub server_name: String,
    pub alpn: String,
}

#[derive(Debug)]
pub enum Parse {
    Incomplete,
    Invalid(String),
    Complete(ClientHello),
}

fn u16(data: &[u8], offset: usize) -> usize {
    ((data[offset] as usize) << 8) | data[offset + 1] as usize
}

pub fn parse_client_hello(data: &[u8]) -> Parse {
    let mut handshake: Vec<u8> = Vec::new();
    let mut record_offset = 0usize;
    let mut handshake_length: Option<usize> = None;

    while record_offset < data.len() {
        if data.len() - record_offset < 5 {
            return Parse::Incomplete;
        }
        if data[record_offset] != 0x16 {
            return Parse::Invalid("expected TLS handshake record".into());
        }
        let record_length = u16(data, record_offset + 3);
        if data.len() - record_offset - 5 < record_length {
            return Parse::Incomplete;
        }
        let start = record_offset + 5;
        handshake.extend_from_slice(&data[start..start + record_length]);
        record_offset = start + record_length;

        if handshake.len() >= 4 {
            if handshake[0] != 0x01 {
                return Parse::Invalid("expected TLS ClientHello".into());
            }
            if handshake_length.is_none() {
                handshake_length = Some(
                    ((handshake[1] as usize) << 16)
                        | ((handshake[2] as usize) << 8)
                        | handshake[3] as usize,
                );
            }
            if handshake.len() >= handshake_length.unwrap() + 4 {
                break;
            }
        }
    }

    let handshake_length = match handshake_length {
        Some(len) if handshake.len() >= len + 4 => len,
        _ => return Parse::Incomplete,
    };

    let hello = &handshake[4..handshake_length + 4];
    let mut offset = 0usize;

    if hello.len() < 35 {
        return Parse::Invalid("truncated ClientHello".into());
    }
    offset += 2 + 32; // version + random

    let session_length = hello[offset] as usize;
    offset += 1 + session_length;
    if offset + 2 > hello.len() {
        return Parse::Invalid("invalid session".into());
    }

    let cipher_length = u16(hello, offset);
    offset += 2 + cipher_length;
    if offset >= hello.len() {
        return Parse::Invalid("invalid cipher suites".into());
    }

    let compression_length = hello[offset] as usize;
    offset += 1 + compression_length;
    if offset == hello.len() {
        return Parse::Invalid("ClientHello has no SNI".into());
    }
    if offset + 2 > hello.len() {
        return Parse::Invalid("invalid extensions".into());
    }

    let extensions_length = u16(hello, offset);
    offset += 2;
    let extensions_end = offset + extensions_length;
    if extensions_end > hello.len() {
        return Parse::Invalid("truncated extensions".into());
    }

    let mut server_name = String::new();
    let mut alpn = String::new();

    while offset + 4 <= extensions_end {
        let ext_type = u16(hello, offset);
        let length = u16(hello, offset + 2);
        offset += 4;
        let end = offset + length;
        if end > extensions_end {
            return Parse::Invalid("truncated extension".into());
        }

        if ext_type == 0 && length >= 5 {
            // server_name
            let list_end = (offset + 2 + u16(hello, offset)).min(end);
            let mut name_offset = offset + 2;
            while name_offset + 3 <= list_end {
                let name_type = hello[name_offset];
                let name_length = u16(hello, name_offset + 1);
                name_offset += 3;
                if name_offset + name_length > list_end {
                    break;
                }
                if name_type == 0 {
                    server_name = String::from_utf8_lossy(
                        &hello[name_offset..name_offset + name_length],
                    )
                    .into_owned();
                    break;
                }
                name_offset += name_length;
            }
        } else if ext_type == 16 && length >= 3 {
            // application_layer_protocol_negotiation
            let list_end = (offset + 2 + u16(hello, offset)).min(end);
            let protocol_length = hello[offset + 2] as usize;
            if offset + 3 + protocol_length <= list_end {
                alpn = String::from_utf8_lossy(
                    &hello[offset + 3..offset + 3 + protocol_length],
                )
                .into_owned();
            }
        }

        offset = end;
    }

    if server_name.is_empty() {
        return Parse::Invalid("ClientHello has no SNI".into());
    }
    Parse::Complete(ClientHello {
        server_name: server_name.to_lowercase(),
        alpn,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal but well-formed TLS 1.2 ClientHello carrying the
    /// given SNI (and optional ALPN), for parser tests.
    fn build_client_hello(sni: &str, alpn: Option<&str>) -> Vec<u8> {
        let mut extensions: Vec<u8> = Vec::new();

        // server_name extension (type 0)
        let name = sni.as_bytes();
        let mut sn_body: Vec<u8> = Vec::new();
        sn_body.push(0); // host_name
        sn_body.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sn_body.extend_from_slice(name);
        let mut sn_list: Vec<u8> = Vec::new();
        sn_list.extend_from_slice(&(sn_body.len() as u16).to_be_bytes());
        sn_list.extend_from_slice(&sn_body);
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sn_list.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sn_list);

        // alpn extension (type 16)
        if let Some(proto) = alpn {
            let p = proto.as_bytes();
            let mut alpn_body: Vec<u8> = Vec::new();
            alpn_body.extend_from_slice(&((p.len() + 1) as u16).to_be_bytes());
            alpn_body.push(p.len() as u8);
            alpn_body.extend_from_slice(p);
            extensions.extend_from_slice(&16u16.to_be_bytes());
            extensions.extend_from_slice(&(alpn_body.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_body);
        }

        let mut hello: Vec<u8> = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]); // legacy version
        hello.extend_from_slice(&[0xAA; 32]); // random
        hello.push(0); // session id length
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        hello.push(1); // compression methods length
        hello.push(0); // null compression
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake: Vec<u8> = Vec::new();
        handshake.push(0x01); // ClientHello
        let len = hello.len() as u32;
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&hello);

        let mut record: Vec<u8> = Vec::new();
        record.push(0x16); // handshake
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn parses_sni_and_alpn() {
        let bytes = build_client_hello("Api.Tunnel.Example.COM", Some("h2"));
        match parse_client_hello(&bytes) {
            Parse::Complete(hello) => {
                assert_eq!(hello.server_name, "api.tunnel.example.com");
                assert_eq!(hello.alpn, "h2");
            }
            other => panic!("expected complete, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_on_truncation() {
        let bytes = build_client_hello("x.example.com", None);
        assert!(matches!(
            parse_client_hello(&bytes[..10]),
            Parse::Incomplete
        ));
    }

    #[test]
    fn rejects_non_tls() {
        assert!(matches!(
            parse_client_hello(b"GET / HTTP/1.1\r\n\r\n"),
            Parse::Invalid(_)
        ));
    }
}
