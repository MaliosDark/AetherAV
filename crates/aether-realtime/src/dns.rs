//! Outbound DNS query monitoring.
//!
//! Watching the host's DNS lookups catches contact with a known-bad domain
//! *before* the TCP connection is even made. The pure [`parse_query_name`]
//! turns a captured DNS message into the queried name; the optional `pcap`
//! sniffer ([`watch_dns_queries`], feature `pcap`) provides the live packet
//! source (which needs libpcap + root, like the kernel `EventSource`s).

/// Extract the queried name (QNAME) from a raw DNS message (UDP payload).
///
/// Returns the dotted name of the first question, e.g. `evil.example`.
/// Rejects messages with no question or with name-compression in the question
/// (compression never appears there in practice).
pub fn parse_query_name(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    // QDCOUNT (questions) must be >= 1.
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12; // skip the 12-byte header
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer - not valid in a question
        }
        let end = pos.checked_add(len)?;
        let label = msg.get(pos..end)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = end;
        if labels.len() > 127 {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join(".").to_lowercase())
}

/// Locate the UDP payload inside a captured link-layer frame.
#[cfg(feature = "pcap")]
fn udp_payload(data: &[u8], linktype: pcap::Linktype) -> Option<&[u8]> {
    // Strip the link-layer header.
    let l2 = match linktype {
        pcap::Linktype::ETHERNET => 14,
        pcap::Linktype::NULL | pcap::Linktype(108) => 4, // loopback (DLT_NULL/LOOP)
        _ => 14,
    };
    let ip = data.get(l2..)?;
    if ip.is_empty() {
        return None;
    }
    let version = ip[0] >> 4;
    let (proto, l3) = match version {
        4 => {
            let ihl = (ip[0] & 0x0f) as usize * 4;
            (*ip.get(9)?, ihl)
        }
        6 => (*ip.get(6)?, 40), // next-header; assumes no extension headers
        _ => return None,
    };
    if proto != 17 {
        return None; // not UDP
    }
    let udp = ip.get(l3..)?;
    udp.get(8..) // skip the 8-byte UDP header -> DNS payload
}

/// Live DNS query sniffer (feature `pcap`; needs libpcap + capture privileges).
/// Calls `on_query` with every queried domain seen on UDP/53.
#[cfg(feature = "pcap")]
pub fn watch_dns_queries<F: FnMut(String)>(mut on_query: F) -> Result<(), String> {
    use pcap::{Capture, Device};
    let dev = Device::lookup()
        .map_err(|e| e.to_string())?
        .ok_or("no capture device")?;
    let mut cap = Capture::from_device(dev)
        .map_err(|e| e.to_string())?
        .immediate_mode(true)
        .open()
        .map_err(|e| e.to_string())?;
    cap.filter("udp port 53", true).map_err(|e| e.to_string())?;
    let linktype = cap.get_datalink();
    while let Ok(packet) = cap.next_packet() {
        if let Some(payload) = udp_payload(packet.data, linktype) {
            if let Some(q) = parse_query_name(payload) {
                on_query(q);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qname_from_query() {
        // DNS query for "evil.example": header + QNAME + QTYPE(A) + QCLASS(IN).
        let mut msg = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: standard query, RD
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar = 0
        ];
        msg.push(4);
        msg.extend_from_slice(b"evil");
        msg.push(7);
        msg.extend_from_slice(b"example");
        msg.push(0); // root
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        assert_eq!(parse_query_name(&msg).as_deref(), Some("evil.example"));
    }

    #[test]
    fn rejects_empty_or_truncated() {
        assert!(parse_query_name(&[0u8; 4]).is_none());
        // qdcount = 0
        let mut m = vec![0u8; 12];
        m[5] = 0;
        assert!(parse_query_name(&m).is_none());
    }
}
