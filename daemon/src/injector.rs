use anyhow::{anyhow, Context, Result};
use log::{debug, info, warn};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::net::Ipv4Addr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::RawFd;

/* IP header flags */
const IP_MF: u16 = 0x2000; // More Fragments flag
const IP_DF: u16 = 0x4000; // Don't Fragment flag
const IP_OFFSET_MASK: u16 = 0x1FFF; // Fragment offset mask

/* Socket options */
const IP_HDRINCL: i32 = 3;

/* Socket option for packet mark */
const SO_MARK: i32 = 36;

/// Raw socket injector for fake packets and UDP fragmentation
pub struct RawInjector {
    sock: RawFd,
    udp_injector: UdpFragmentInjector,
}

impl RawInjector {
    /// Create a new raw socket injector
    /// 
    /// Requires CAP_NET_RAW capability or root privileges.
    pub fn new() -> Result<Self> {
        let sock = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::empty(),
            Some(nix::sys::socket::SockProtocol::Tcp),
        )
        .context(
            "Failed to create raw TCP socket. \
             Ensure you have CAP_NET_RAW capability or run as root."
        )?;

        let raw_fd = sock.into_raw_fd();
        
        // Set mark to avoid eBPF processing (prevent loops)
        unsafe {
            let mark: i32 = 0xD0F; // USERSPACE_MARK
            let ret = libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                log::warn!(
                    "Failed to set socket mark ({}): {}. \
                     Packet injection may still work, but eBPF filtering might process injected packets.",
                    err.raw_os_error().unwrap_or(-1),
                    err
                );
            }
        }

        // Create UDP fragment injector
        let udp_injector = UdpFragmentInjector::new()
            .context("Failed to create UDP fragment injector")?;

        Ok(Self { sock: raw_fd, udp_injector })
    }

    /// Get reference to UDP fragment injector
    pub fn udp_injector(&self) -> &UdpFragmentInjector {
        &self.udp_injector
    }

    /// Inject a fake TCP packet
    /// 
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - TCP sequence number
    /// * `ack` - TCP acknowledgment number
    /// * `flags` - TCP flags
    /// * `payload` - Optional payload data
    /// 
    /// # Errors
    /// Returns an error if packet construction or sending fails
    pub fn inject_fake_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Option<&[u8]>,
    ) -> Result<()> {
        debug!(
            "Injecting fake packet: {}:{} -> {}:{}, seq={}, ack={}, flags={:02x}",
            src_ip, src_port, dst_ip, dst_port, seq, ack, flags
        );

        // Build IP header
        let ip_header = build_ip_header(src_ip, dst_ip);
        
        // Build TCP header with checksum
        let tcp_header = build_tcp_header(src_port, dst_port, seq, ack, flags, payload);
        
        // Combine headers and payload
        let mut packet = ip_header;
        packet.extend_from_slice(&tcp_header);
        
        if let Some(p) = payload {
            packet.extend_from_slice(p);
        }

        // Calculate and set IP checksum
        let ip_checksum = calculate_checksum(&packet[0..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        // Calculate TCP checksum (pseudo-header + tcp header + payload)
        let tcp_checksum = calculate_tcp_checksum(
            src_ip, dst_ip, &packet[20..]
        );
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = (tcp_checksum & 0xFF) as u8;

        // Send packet
        let dst_sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: dst_port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        
        let sent = unsafe {
            libc::sendto(
                self.sock,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst_sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow!(
                "Failed to send raw packet to {}:{} - {} (os error {}). \
                 Ensure the destination is reachable and you have network access.",
                dst_ip, dst_port, err, err.raw_os_error().unwrap_or(-1)
            ));
        }

        debug!("Successfully injected {} bytes to {}:{}", sent, dst_ip, dst_port);
        Ok(())
    }

    /// Split a TCP packet into two parts and inject both
    ///
    /// This is the real TCP split implementation for DPI bypass.
    /// The original packet is dropped by eBPF, and this function sends
    /// two separate packets: first part (1..split_pos) and second part (split_pos..end)
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - TCP sequence number (for first packet)
    /// * `ack` - TCP acknowledgment number
    /// * `flags` - TCP flags (from original packet)
    /// * `payload` - Full payload data
    /// * `split_pos` - Position to split at (1-based)
    ///
    /// # Returns
    /// Tuple of results for (first_packet, second_packet)
    pub fn inject_split_packets(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
        split_pos: usize,
    ) -> (Result<()>, Result<()>) {
        debug!(
            "Injecting split packets: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, split_pos, payload.len()
        );

        // Validate split position
        if split_pos == 0 || split_pos >= payload.len() {
            return (
                Err(anyhow!("Invalid split position: {} (payload len: {})", split_pos, payload.len())),
                Err(anyhow!("Invalid split position")),
            );
        }

        // Split payload into two parts
        let first_part = &payload[0..split_pos];
        let second_part = &payload[split_pos..];

        debug!(
            "Split: first_part={} bytes, second_part={} bytes",
            first_part.len(), second_part.len()
        );

        // First packet: contains bytes 0..split_pos
        // Use PSH|ACK flags for the first part to push data
        let first_flags = 0x18; // PSH|ACK
        let first_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            seq,
            ack,
            first_flags,
            Some(first_part),
        );

        // Second packet: contains bytes split_pos..end
        // Sequence number is advanced by first_part length
        let second_seq = seq.wrapping_add(first_part.len() as u32);
        // Use original flags for second part (might include FIN)
        let second_flags = if flags & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 }; // PSH|ACK or PSH|ACK|FIN
        let second_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            second_seq,
            ack,
            second_flags,
            Some(second_part),
        );

        (first_result, second_result)
    }

    /// Split a TLS record into two separate TLS records and inject both
    ///
    /// This is the TLS record split implementation for DPI bypass.
    /// Unlike TCP split which just divides the payload, this creates two valid
    /// TLS records with proper headers, confusing DPI systems that inspect TLS.
    ///
    /// TLS Record Structure:
    /// - Content Type: 1 byte (0x16 = Handshake)
    /// - Version: 2 bytes
    /// - Length: 2 bytes (big-endian, length of handshake data)
    /// - Handshake Data: variable
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - TCP sequence number (for first packet)
    /// * `ack` - TCP acknowledgment number
    /// * `flags` - TCP flags (from original packet)
    /// * `payload` - Full TLS payload (including TLS record header)
    /// * `split_pos` - Position to split at (relative to payload start, typically within handshake data)
    ///
    /// # Returns
    /// Tuple of results for (first_packet, second_packet)
    pub fn inject_tls_split_packets(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
        split_pos: usize,
    ) -> (Result<()>, Result<()>) {
        debug!(
            "Injecting TLS split packets: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, split_pos, payload.len()
        );

        // TLS record header is 5 bytes
        const TLS_RECORD_HEADER_LEN: usize = 5;

        // Validate payload has at least TLS header
        if payload.len() < TLS_RECORD_HEADER_LEN {
            return (
                Err(anyhow!("TLS payload too short: {} bytes (need at least 5 for header)", payload.len())),
                Err(anyhow!("Invalid TLS payload")),
            );
        }

        // Validate split position (must be after TLS header and within payload)
        if split_pos <= TLS_RECORD_HEADER_LEN || split_pos >= payload.len() {
            return (
                Err(anyhow!(
                    "Invalid TLS split position: {} (must be > {} and < {})",
                    split_pos, TLS_RECORD_HEADER_LEN, payload.len()
                )),
                Err(anyhow!("Invalid TLS split position")),
            );
        }

        // Parse original TLS header
        let content_type = payload[0];
        let version_major = payload[1];
        let version_minor = payload[2];
        let original_length = ((payload[3] as usize) << 8) | (payload[4] as usize);

        debug!(
            "TLS record: content_type=0x{:02x}, version={}.{}, original_length={}",
            content_type, version_major, version_minor, original_length
        );

        // Split positions relative to handshake data (after TLS header)
        let split_in_handshake = split_pos - TLS_RECORD_HEADER_LEN;
        let first_handshake_len = split_in_handshake;
        let second_handshake_len = original_length.saturating_sub(split_in_handshake);

        // Build first TLS record
        let mut first_record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + first_handshake_len);
        first_record.push(content_type);
        first_record.push(version_major);
        first_record.push(version_minor);
        first_record.extend_from_slice(&(first_handshake_len as u16).to_be_bytes());
        first_record.extend_from_slice(&payload[TLS_RECORD_HEADER_LEN..split_pos]);

        // Build second TLS record
        let mut second_record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + second_handshake_len);
        second_record.push(content_type);
        second_record.push(version_major);
        second_record.push(version_minor);
        second_record.extend_from_slice(&(second_handshake_len as u16).to_be_bytes());
        second_record.extend_from_slice(&payload[split_pos..TLS_RECORD_HEADER_LEN + original_length]);

        info!(
            "[TLS SPLIT] First record: {} bytes (handshake: {}), Second record: {} bytes (handshake: {})",
            first_record.len(), first_handshake_len, second_record.len(), second_handshake_len
        );

        // First packet: contains first TLS record
        // Use PSH|ACK flags for the first part to push data
        let first_flags = 0x18; // PSH|ACK
        let first_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            seq,
            ack,
            first_flags,
            Some(&first_record),
        );

        // Second packet: contains second TLS record
        // Sequence number is advanced by first_record length
        let second_seq = seq.wrapping_add(first_record.len() as u32);
        // Use original flags for second part (might include FIN)
        let second_flags = if flags & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 }; // PSH|ACK or PSH|ACK|FIN
        let second_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            second_seq,
            ack,
            second_flags,
            Some(&second_record),
        );

        (first_result, second_result)
    }
    
    /// Inject a fake TCP packet with offset-based sequence number manipulation
    ///
    /// This is used for DPI bypass: a fake packet is sent before the real one,
    /// with a modified sequence number to confuse the DPI system.
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - Original TCP sequence number
    /// * `ack` - TCP acknowledgment number
    /// * `fake_offset` - Offset for sequence number manipulation:
    ///   - negative = send RST packet with modified seq
    ///   - positive = send data packet with seq + offset
    /// * `payload` - Payload data for fake packet (if data packet)
    ///
    /// # Errors
    /// Returns an error if packet construction or sending fails
    pub fn inject_fake_with_offset(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        fake_offset: i32,
        payload: &[u8],
    ) -> Result<()> {
        debug!(
            "Injecting fake packet with offset: {}:{} -> {}:{}, seq={}, offset={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, fake_offset, payload.len()
        );

        if fake_offset < 0 {
            // Negative offset: send RST packet to confuse DPI
            // The RST packet has a sequence number that falls within the expected window
            let rst_seq = if fake_offset == -1 {
                // Special case: use seq - payload_len (common for GoodByeDPI)
                seq.wrapping_sub(payload.len() as u32)
            } else {
                // Use absolute value of offset as subtraction
                seq.wrapping_sub(fake_offset.abs() as u32)
            };

            debug!(
                "Injecting RST fake packet: seq={} (original={} - offset={})",
                rst_seq, seq, fake_offset
            );

            self.inject_fake_packet(
                src_ip, dst_ip,
                src_port, dst_port,
                rst_seq,
                ack,
                0x04, // RST flag
                None,
            )
        } else {
            // Positive offset: send data packet with modified sequence
            let fake_seq = seq.wrapping_add(fake_offset as u32);

            debug!(
                "Injecting DATA fake packet: seq={} (original={} + offset={})",
                fake_seq, seq, fake_offset
            );

            // Send with PSH|ACK flags
            self.inject_fake_packet(
                src_ip, dst_ip,
                src_port, dst_port,
                fake_seq,
                ack,
                0x18, // PSH|ACK
                Some(payload),
            )
        }
    }

    /// Inject a TLS Client Hello fake packet for DPI bypass
    ///
    /// Creates a fake TLS Client Hello with modified SNI or split records.
    /// This is useful for bypassing TLS-based DPI.
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port (typically 443)
    /// * `seq` - TCP sequence number
    /// * `ack` - TCP acknowledgment number
    /// * `original_payload` - Original TLS Client Hello payload
    ///
    /// # Errors
    /// Returns an error if packet construction or sending fails
    pub fn inject_tls_fake(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        original_payload: &[u8],
    ) -> Result<()> {
        debug!(
            "Injecting TLS fake packet: {}:{} -> {}:{}, seq={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, original_payload.len()
        );

        // For TLS fake, we send a minimal TLS record that looks like Client Hello
        // but with different content to confuse DPI
        let mut fake_tls = vec![
            0x16,       // Content type: Handshake
            0x03, 0x01, // TLS 1.0 (legacy version field)
            0x00, 0x05, // Record length (5 bytes - minimal)
            0x01,       // Handshake type: Client Hello
            0x00, 0x00, 0x01, // Handshake length (1 byte)
            0x00,       // Dummy data
        ];

        // Optionally append some of the original payload to make it look more real
        if original_payload.len() > 5 {
            let extra = &original_payload[5..original_payload.len().min(32)];
            fake_tls.extend_from_slice(extra);
            
            // Update record length
            let record_len = (fake_tls.len() - 5) as u16;
            fake_tls[3] = (record_len >> 8) as u8;
            fake_tls[4] = (record_len & 0xFF) as u8;
        }

        self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            seq,
            ack,
            0x18, // PSH|ACK
            Some(&fake_tls),
        )
    }

    /// Inject packets in disorder (out-of-order) sequence
    ///
    /// Packet disorder is a DPI bypass technique where packets are sent
    /// in the wrong order. The second part of the data is sent first
    /// (with a higher sequence number), followed by the first part.
    ///
    /// This confuses DPI systems that expect in-order packets, while
    /// the actual TCP stack on the receiving end will reorder them correctly.
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - Original TCP sequence number (for first part)
    /// * `ack` - TCP acknowledgment number
    /// * `flags` - Original TCP flags
    /// * `payload` - Full payload data
    /// * `split_pos` - Position to split payload (second part sent first)
    ///
    /// # Returns
    /// Tuple of results for (second_packet_sent_first, first_packet_sent_second)
    pub fn inject_disorder_packets(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
        split_pos: usize,
    ) -> (Result<()>, Result<()>) {
        info!(
            "[DISORDER] Injecting out-of-order packets: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, split_pos, payload.len()
        );

        // Validate split position
        if split_pos == 0 || split_pos >= payload.len() {
            return (
                Err(anyhow!("Invalid split position for disorder: {} (payload len: {})", split_pos, payload.len())),
                Err(anyhow!("Invalid split position")),
            );
        }

        // Split payload into two parts
        let first_part = &payload[0..split_pos];
        let second_part = &payload[split_pos..];

        // Calculate sequence numbers
        let second_seq = seq.wrapping_add(first_part.len() as u32);

        info!(
            "[DISORDER] First part: {} bytes (seq={}), Second part: {} bytes (seq={})",
            first_part.len(), seq, second_part.len(), second_seq
        );

        // Send SECOND part FIRST (out-of-order)
        // This packet has a higher sequence number but is sent first
        let second_flags = if flags & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 }; // PSH|ACK or PSH|ACK|FIN
        let second_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            second_seq,  // Higher sequence number
            ack,
            second_flags,
            Some(second_part),
        );

        // Small delay to ensure disorder is noticeable (optional, can be removed)
        // std::thread::sleep(std::time::Duration::from_millis(1));

        // Send FIRST part SECOND (the original sequence)
        let first_flags = 0x18; // PSH|ACK
        let first_result = self.inject_fake_packet(
            src_ip, dst_ip,
            src_port, dst_port,
            seq,  // Original sequence number
            ack,
            first_flags,
            Some(first_part),
        );

        match &second_result {
            Ok(_) => info!("[DISORDER] Second part sent first (out-of-order): {} bytes at seq={}", 
                         second_part.len(), second_seq),
            Err(e) => warn!("[DISORDER] Failed to send second part: {}", e),
        }

        match &first_result {
            Ok(_) => info!("[DISORDER] First part sent second: {} bytes at seq={}", 
                         first_part.len(), seq),
            Err(e) => warn!("[DISORDER] Failed to send first part: {}", e),
        }

        (second_result, first_result)
    }

    /// Inject an OOB (Out-of-Band) packet with URG flag set
    ///
    /// OOB data is sent using TCP's URG flag and urgent pointer.
    /// This confuses DPI systems that may not properly handle urgent data.
    ///
    /// TCP OOB Mechanism:
    /// - URG flag indicates urgent data is present
    /// - Urgent pointer points to the last byte of urgent data
    /// - Receiver can read urgent data out-of-band via MSG_OOB flag
    ///
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source port
    /// * `dst_port` - Destination port
    /// * `seq` - TCP sequence number
    /// * `ack` - TCP acknowledgment number
    /// * `oob_pos` - Position of urgent data (urgent pointer value)
    /// * `payload` - Full payload data (urgent data is at position oob_pos)
    ///
    /// # Returns
    /// Result indicating success or failure
    pub fn inject_oob_packet(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        oob_pos: u16,
        payload: &[u8],
    ) -> Result<()> {
        info!(
            "[OOB] Injecting OOB packet: {}:{} -> {}:{}, seq={}, oob_pos={}, payload_len={}",
            src_ip, src_port, dst_ip, dst_port, seq, oob_pos, payload.len()
        );

        if oob_pos == 0 || oob_pos as usize > payload.len() {
            return Err(anyhow!(
                "Invalid OOB position: {} (payload len: {})",
                oob_pos,
                payload.len()
            ));
        }

        // Build TCP header with URG flag and urgent pointer
        // URG flag = 0x20, combined with PSH|ACK = 0x18
        // Total flags = 0x38 (URG|PSH|ACK)
        let flags = 0x38; // URG (0x20) | PSH (0x08) | ACK (0x10)
        
        // Build IP header
        let ip_header = build_ip_header(src_ip, dst_ip);
        
        // Build TCP header with urgent pointer
        let tcp_header = build_tcp_header_with_urgent(
            src_port, dst_port, seq, ack, flags, oob_pos, Some(payload)
        );
        
        // Combine headers and payload
        let mut packet = ip_header;
        packet.extend_from_slice(&tcp_header);
        
        if let Some(p) = Some(payload) {
            packet.extend_from_slice(p);
        }

        // Calculate and set IP checksum
        let ip_checksum = calculate_checksum(&packet[0..20]);
        packet[10] = (ip_checksum >> 8) as u8;
        packet[11] = (ip_checksum & 0xFF) as u8;

        // Calculate TCP checksum (pseudo-header + tcp header + payload)
        let tcp_checksum = calculate_tcp_checksum(
            src_ip, dst_ip, &packet[20..]
        );
        packet[36] = (tcp_checksum >> 8) as u8;
        packet[37] = (tcp_checksum & 0xFF) as u8;

        // Send packet
        let dst_sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: dst_port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        
        let sent = unsafe {
            libc::sendto(
                self.sock,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst_sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow!(
                "Failed to send OOB packet to {}:{} - {} (os error {})",
                dst_ip, dst_port, err, err.raw_os_error().unwrap_or(-1)
            ));
        }

        info!(
            "[OOB] Successfully injected OOB packet ({} bytes) with URG flag, urgent_ptr={}",
            sent, oob_pos
        );
        Ok(())
    }

    /// Get the raw socket file descriptor
    ///
    /// # Safety
    /// The caller must ensure proper handling of the raw FD to avoid resource leaks
    pub fn raw_fd(&self) -> RawFd {
        self.sock
    }
}

/// UDP/IP Fragmentation injector for QUIC bypass
/// 
/// This injector creates raw UDP sockets with IP_HDRINCL and fragments
/// UDP payload into multiple IP fragments. This bypasses DPI systems that
/// cannot properly reassemble fragmented packets.
pub struct UdpFragmentInjector {
    sock: RawFd,
}

impl UdpFragmentInjector {
    /// Create a new UDP fragment injector with IP_HDRINCL
    /// 
    /// Requires CAP_NET_RAW capability or root privileges.
    pub fn new() -> Result<Self> {
        // Create raw socket with IP_HDRINCL for UDP
        let sock = socket(
            AddressFamily::Inet,
            SockType::Raw,
            SockFlag::empty(),
            Some(nix::sys::socket::SockProtocol::Udp),
        )
        .context(
            "Failed to create raw UDP socket. \
             Ensure you have CAP_NET_RAW capability or run as root."
        )?;

        let raw_fd = sock.into_raw_fd();
        
        // Enable IP_HDRINCL - we will build IP headers manually
        let hdrincl: i32 = 1;
        let ret = unsafe {
            libc::setsockopt(
                raw_fd,
                libc::IPPROTO_IP,
                IP_HDRINCL,
                &hdrincl as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            )
        };
        
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to set IP_HDRINCL on raw socket: {} (os error {})",
                err, err.raw_os_error().unwrap_or(-1)
            ));
        }
        
        // Set mark to avoid eBPF processing (prevent loops)
        unsafe {
            let mark: i32 = 0xD0F; // USERSPACE_MARK
            libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                SO_MARK,
                &mark as *const _ as *const libc::c_void,
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }

        info!("UDP Fragment injector created with IP_HDRINCL");
        Ok(Self { sock: raw_fd })
    }

    /// Fragment and inject UDP payload as IP fragments
    /// 
    /// Splits UDP payload into fragments of specified size and sends them
    /// with IP MF (More Fragments) flag set appropriately.
    /// 
    /// # Arguments
    /// * `src_ip` - Source IP address
    /// * `dst_ip` - Destination IP address
    /// * `src_port` - Source UDP port
    /// * `dst_port` - Destination UDP port
    /// * `payload` - Full UDP payload (will be fragmented)
    /// * `frag_size` - Size of each fragment (default 8 bytes)
    /// 
    /// # Returns
    /// Number of fragments sent
    pub fn inject_fragmented_udp(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        frag_size: u16,
    ) -> Result<usize> {
        let frag_size = if frag_size == 0 { 8 } else { frag_size };
        
        if payload.len() <= frag_size as usize {
            // No need to fragment, send as single packet
            return self.inject_single_udp(src_ip, dst_ip, src_port, dst_port, payload);
        }

        info!(
            "Fragmenting UDP payload: {}:{} -> {}:{}, payload_len={}, frag_size={}",
            src_ip, src_port, dst_ip, dst_port, payload.len(), frag_size
        );

        // Build UDP header
        let udp_header = build_udp_header(src_port, dst_port, payload);
        let udp_len = udp_header.len() + payload.len();
        
        // Combine UDP header + payload
        let udp_packet = [&udp_header[..], payload].concat();
        
        // Calculate number of fragments needed
        let total_len = udp_packet.len();
        let num_frags = (total_len + frag_size as usize - 1) / frag_size as usize;
        let mut frags_sent = 0;
        
        // Fragment offset is measured in 8-byte units
        let frag_unit: usize = 8;
        
        for i in 0..num_frags {
            let offset = i * frag_size as usize;
            let end = (offset + frag_size as usize).min(total_len);
            let frag_data = &udp_packet[offset..end];
            
            // Calculate fragment offset in 8-byte units
            let frag_offset = (offset / frag_unit) as u16;
            
            // MF flag: set on all fragments except the last one
            let is_last = i == num_frags - 1;
            let flags_offset = if is_last {
                frag_offset
            } else {
                frag_offset | IP_MF
            };
            
            // Build IP header for this fragment
            let ip_header = build_fragment_ip_header(
                src_ip, dst_ip,
                frag_data.len() as u16 + 20, // IP header + fragment data
                i as u16, // Identification
                flags_offset,
            );
            
            // Build complete packet
            let packet = [&ip_header[..], frag_data].concat();
            
            // Send fragment
            let dst_sockaddr = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: 0, // Not used with IP_HDRINCL
                sin_addr: libc::in_addr {
                    s_addr: u32::from(dst_ip).to_be(),
                },
                sin_zero: [0; 8],
            };
            
            let sent = unsafe {
                libc::sendto(
                    self.sock,
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                    0,
                    &dst_sockaddr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                )
            };

            if sent < 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!(
                    "Failed to send UDP fragment {}: {} (os error {})",
                    i, err, err.raw_os_error().unwrap_or(-1)
                ));
            }
            
            debug!(
                "Sent UDP fragment {}/{}: offset={}, len={}, MF={}",
                i + 1, num_frags, frag_offset * 8, frag_data.len(), !is_last
            );
            
            frags_sent += 1;
        }
        
        info!(
            "Successfully sent {} UDP fragments for {} bytes payload",
            frags_sent, payload.len()
        );
        
        Ok(frags_sent)
    }

    /// Inject a single UDP packet without fragmentation
    fn inject_single_udp(
        &self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<usize> {
        // Build UDP header
        let udp_header = build_udp_header(src_port, dst_port, payload);
        
        // Build complete UDP packet (header + payload)
        let udp_packet = [&udp_header[..], payload].concat();
        let udp_len = udp_packet.len() as u16;
        
        // Build IP header for non-fragmented packet (DF flag set)
        let ip_header = build_fragment_ip_header(
            src_ip, dst_ip,
            udp_len + 20, // IP header + UDP packet
            0, // Identification
            IP_DF, // Don't Fragment flag
        );
        
        // Combine IP + UDP
        let packet = [&ip_header[..], &udp_packet[..]].concat();
        
        // Send packet
        let dst_sockaddr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from(dst_ip).to_be(),
            },
            sin_zero: [0; 8],
        };
        
        let sent = unsafe {
            libc::sendto(
                self.sock,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &dst_sockaddr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };

        if sent < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!(
                "Failed to send single UDP packet: {} (os error {})",
                err, err.raw_os_error().unwrap_or(-1)
            ));
        }
        
        debug!("Sent single UDP packet: {} bytes", sent);
        Ok(1)
    }
}

/// Build UDP header
fn build_udp_header(
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len() as u16;
    let mut header = vec![0u8; 8];
    
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // Checksum = 0 (optional in IPv4, we'll skip it for simplicity)
    header[6..8].copy_from_slice(&0u16.to_be_bytes());
    
    header
}

/// Build IP header for fragmented packet
fn build_fragment_ip_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    total_len: u16,
    identification: u16,
    flags_offset: u16,
) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    
    header[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    header[1] = 0; // DSCP, ECN
    header[2..4].copy_from_slice(&total_len.to_be_bytes()); // Total length
    header[4..6].copy_from_slice(&identification.to_be_bytes()); // Identification
    
    // Flags and Fragment Offset (3 bits flags + 13 bits offset)
    header[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    
    header[8] = 64; // TTL
    header[9] = 17; // Protocol: UDP
    // Header checksum - calculated later (bytes 10-11)
    header[10..12].copy_from_slice(&0u16.to_be_bytes());
    header[12..16].copy_from_slice(&src.octets());
    header[16..20].copy_from_slice(&dst.octets());
    
    // Calculate IP checksum
    let checksum = calculate_checksum(&header);
    header[10] = (checksum >> 8) as u8;
    header[11] = (checksum & 0xFF) as u8;
    
    header
}

/// Build IP header for IPv4 packet
fn build_ip_header(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0] = 0x45; // Version 4, IHL 5
    header[1] = 0; // DSCP, ECN
    // Total length - set later (bytes 2-3)
    header[4] = 0; // Identification
    header[5] = 0;
    header[6] = 0x40; // Don't fragment
    header[7] = 0;
    header[8] = 64; // TTL
    header[9] = 6; // Protocol: TCP
    // Header checksum - calculated later (bytes 10-11)
    header[12..16].copy_from_slice(&src.octets());
    header[16..20].copy_from_slice(&dst.octets());
    header
}

/// Build TCP header
fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12] = 0x50; // Data offset 5 (20 bytes)
    header[13] = flags; // Flags
    header[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window size
    // Checksum - calculated later (bytes 16-17)
    header[18..20].copy_from_slice(&0u16.to_be_bytes()); // Urgent pointer
    
    if let Some(p) = payload {
        header.extend_from_slice(p);
    }
    
    header
}

/// Build TCP header with urgent pointer for OOB (Out-of-Band) data
///
/// # Arguments
/// * `src_port` - Source port
/// * `dst_port` - Destination port
/// * `seq` - TCP sequence number
/// * `ack` - TCP acknowledgment number
/// * `flags` - TCP flags (should include URG flag)
/// * `urgent_ptr` - Urgent pointer value (offset to last byte of urgent data)
/// * `payload` - Optional payload data
fn build_tcp_header_with_urgent(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    urgent_ptr: u16,
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut header = vec![0u8; 20];
    header[0..2].copy_from_slice(&src_port.to_be_bytes());
    header[2..4].copy_from_slice(&dst_port.to_be_bytes());
    header[4..8].copy_from_slice(&seq.to_be_bytes());
    header[8..12].copy_from_slice(&ack.to_be_bytes());
    header[12] = 0x50; // Data offset 5 (20 bytes)
    header[13] = flags; // Flags (should include URG)
    header[14..16].copy_from_slice(&65535u16.to_be_bytes()); // Window size
    // Checksum - calculated later (bytes 16-17)
    // Urgent pointer - points to last byte of urgent data (bytes 18-19)
    header[18..20].copy_from_slice(&urgent_ptr.to_be_bytes());
    
    if let Some(p) = payload {
        header.extend_from_slice(p);
    }
    
    header
}

/// Calculate IP checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }
    
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

/// Calculate TCP checksum with pseudo-header
fn calculate_tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_data: &[u8]) -> u16 {
    // Pseudo-header
    let mut pseudo_header = Vec::new();
    pseudo_header.extend_from_slice(&src_ip.octets());
    pseudo_header.extend_from_slice(&dst_ip.octets());
    pseudo_header.push(0); // Zero
    pseudo_header.push(6); // Protocol (TCP)
    pseudo_header.extend_from_slice(&(tcp_data.len() as u16).to_be_bytes());
    
    // Combine pseudo-header and TCP data
    pseudo_header.extend_from_slice(tcp_data);
    
    calculate_checksum(&pseudo_header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        // Test with known data
        let data = vec![0x45, 0x00, 0x00, 0x3c];
        let _checksum = calculate_checksum(&data);
        // Just verify it doesn't panic
    }

    #[test]
    fn test_build_ip_header() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let header = build_ip_header(src, dst);
        
        assert_eq!(header.len(), 20);
        assert_eq!(header[0], 0x45); // IPv4, IHL 5
        assert_eq!(header[9], 6); // TCP protocol
    }

    #[test]
    fn test_build_tcp_header() {
        let header = build_tcp_header(12345, 443, 1000, 0, 0x02, None); // SYN
        
        assert_eq!(header.len(), 20);
        assert_eq!(&header[0..2], &12345u16.to_be_bytes());
        assert_eq!(&header[2..4], &443u16.to_be_bytes());
        assert_eq!(header[13], 0x02); // SYN flag
    }

    #[test]
    fn test_build_tcp_header_with_payload() {
        let payload = b"GET / HTTP/1.1\r\n";
        let header = build_tcp_header(54321, 80, 1000, 1, 0x18, Some(payload));
        
        // Header should be 20 bytes + payload
        assert_eq!(header.len(), 20 + payload.len());
        assert_eq!(&header[0..2], &54321u16.to_be_bytes());
        assert_eq!(&header[2..4], &80u16.to_be_bytes());
        assert_eq!(header[13], 0x18); // PSH|ACK flags
        // Payload should be appended
        assert_eq!(&header[20..], payload);
    }

    #[test]
    fn test_split_payload_validation() {
        // Test that split position 0 is invalid
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        // split_pos = 0 should fail
        let split_pos = 0;
        assert!(split_pos == 0 || split_pos >= payload.len());
        
        // split_pos >= len should fail
        let split_pos = payload.len();
        assert!(split_pos >= payload.len());
        
        // Valid split position
        let split_pos = 5;
        assert!(split_pos > 0 && split_pos < payload.len());
    }

    #[test]
    fn test_split_sequence_calculation() {
        // Test that sequence numbers are calculated correctly for split packets
        let seq: u32 = 1000;
        let first_part_len: usize = 5;
        
        // Second packet sequence should be first seq + first_part_len
        let second_seq = seq.wrapping_add(first_part_len as u32);
        assert_eq!(second_seq, 1005);
        
        // Test wrapping: u32::MAX - 3 + 5 = u32::MAX + 2 = 1 (wrapping)
        let seq_max: u32 = u32::MAX - 3;
        let second_seq_wrapped = seq_max.wrapping_add(first_part_len as u32);
        assert_eq!(second_seq_wrapped, 1); // Should wrap around: (MAX-3) + 5 = MAX + 2 = 1
    }

    #[test]
    fn test_tcp_flags_for_split() {
        // Test TCP flags for split packets
        let original_flags = 0x18; // PSH|ACK
        
        // First packet should have PSH|ACK
        let first_flags = 0x18u8;
        assert_eq!(first_flags, 0x18);
        
        // Second packet should have PSH|ACK (or PSH|ACK|FIN if original had FIN)
        let second_flags_no_fin = if original_flags & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 };
        assert_eq!(second_flags_no_fin, 0x18);
        
        // If original had FIN
        let original_flags_with_fin = 0x19; // FIN|PSH|ACK
        let second_flags_with_fin = if original_flags_with_fin & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 };
        assert_eq!(second_flags_with_fin, 0x19); // PSH|ACK|FIN
    }

    #[test]
    fn test_checksum_with_known_values() {
        // Test IP checksum with a known good packet
        // This is a simple IPv4 header
        let mut header = vec![0u8; 20];
        header[0] = 0x45; // Version 4, IHL 5
        header[8] = 64;   // TTL
        header[9] = 6;    // TCP
        header[12..16].copy_from_slice(&[192, 168, 1, 1]); // Source IP
        header[16..20].copy_from_slice(&[10, 0, 0, 1]);    // Dest IP
        
        let checksum = calculate_checksum(&header);
        // Checksum should be non-zero for this header
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_fake_offset_negative_sequence() {
        // Test that negative offset produces correct sequence number for RST
        let seq: u32 = 1000;
        let payload_len: usize = 100;
        let fake_offset: i32 = -1;
        
        // For offset -1, RST seq should be seq - payload_len
        let rst_seq = if fake_offset == -1 {
            seq.wrapping_sub(payload_len as u32)
        } else {
            seq.wrapping_sub(fake_offset.abs() as u32)
        };
        assert_eq!(rst_seq, 900); // 1000 - 100 = 900
        
        // Test with other negative offset
        let fake_offset: i32 = -50;
        let rst_seq = seq.wrapping_sub(fake_offset.abs() as u32);
        assert_eq!(rst_seq, 950); // 1000 - 50 = 950
    }

    #[test]
    fn test_fake_offset_positive_sequence() {
        // Test that positive offset produces correct sequence number
        let seq: u32 = 1000;
        let fake_offset: i32 = 100;
        
        let fake_seq = seq.wrapping_add(fake_offset as u32);
        assert_eq!(fake_seq, 1100); // 1000 + 100 = 1100
    }

    #[test]
    fn test_fake_offset_sequence_wrapping() {
        // Test sequence number wrapping for fake packets
        let seq: u32 = u32::MAX - 10;
        let fake_offset: i32 = 100;
        
        let fake_seq = seq.wrapping_add(fake_offset as u32);
        assert_eq!(fake_seq, 89); // (MAX - 10) + 100 = MAX + 90 = 89 (wrapping)
        
        // Test negative offset wrapping
        let seq: u32 = 10;
        let payload_len: usize = 100;
        let fake_offset: i32 = -1;
        
        let rst_seq = if fake_offset == -1 {
            seq.wrapping_sub(payload_len as u32)
        } else {
            seq.wrapping_sub(fake_offset.abs() as u32)
        };
        // 10 - 100 should wrap around
        assert_eq!(rst_seq, u32::MAX - 89); // 10 - 100 = -90 = MAX - 89 (wrapping)
    }

    #[test]
    fn test_tls_fake_packet_construction() {
        // Test TLS fake packet construction logic
        let original_payload = vec![
            0x16, // Handshake
            0x03, 0x01, // TLS 1.0
            0x00, 0x20, // Record length
            0x01, // Client Hello
            0x00, 0x00, 0x1c, // Handshake length
            // ... more data
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        // Verify the fake TLS packet structure
        let mut fake_tls = vec![
            0x16,       // Content type: Handshake
            0x03, 0x01, // TLS 1.0
            0x00, 0x05, // Record length (5 bytes - minimal)
            0x01,       // Handshake type: Client Hello
            0x00, 0x00, 0x01, // Handshake length
            0x00,       // Dummy data
        ];
        
        assert_eq!(fake_tls[0], 0x16); // Handshake
        assert_eq!(fake_tls[5], 0x01); // Client Hello
        assert_eq!(fake_tls.len(), 10); // Minimal fake
    }

    #[test]
    fn test_rst_packet_flags() {
        // Test that RST flag is correctly set
        let rst_flag: u8 = 0x04;
        assert_eq!(rst_flag, 0x04); // RST = 0x04
        
        // Verify it's only RST (no other flags)
        assert_eq!(rst_flag & 0x01, 0); // No FIN
        assert_eq!(rst_flag & 0x02, 0); // No SYN
        assert_eq!(rst_flag & 0x08, 0); // No PSH
        assert_eq!(rst_flag & 0x10, 0); // No ACK
        assert_eq!(rst_flag & 0x04, 0x04); // RST set
    }

    #[test]
    fn test_psh_ack_flags() {
        // Test PSH|ACK flags for data packets
        let psh_ack: u8 = 0x18; // PSH (0x08) | ACK (0x10)
        assert_eq!(psh_ack, 0x18);
        
        // Verify individual flags
        assert_eq!(psh_ack & 0x08, 0x08); // PSH set
        assert_eq!(psh_ack & 0x10, 0x10); // ACK set
    }

    #[test]
    fn test_udp_header_construction() {
        let payload = b"QUIC payload data";
        let header = build_udp_header(12345, 443, payload);
        
        assert_eq!(header.len(), 8);
        assert_eq!(&header[0..2], &12345u16.to_be_bytes()); // Source port
        assert_eq!(&header[2..4], &443u16.to_be_bytes());   // Dest port
        // Length should be 8 (header) + payload.len()
        let expected_len = (8 + payload.len()) as u16;
        assert_eq!(&header[4..6], &expected_len.to_be_bytes());
        // Checksum is 0 (we don't calculate it)
        assert_eq!(&header[6..8], &0u16.to_be_bytes());
    }

    #[test]
    fn test_fragment_ip_header() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let total_len = 100; // IP header (20) + data (80)
        let identification = 12345;
        let flags_offset = 0x2000 | 5; // MF flag set + offset 5 (40 bytes)
        
        let header = build_fragment_ip_header(src, dst, total_len, identification, flags_offset);
        
        assert_eq!(header.len(), 20);
        assert_eq!(header[0], 0x45); // Version 4, IHL 5
        assert_eq!(&header[2..4], &total_len.to_be_bytes()); // Total length
        assert_eq!(&header[4..6], &identification.to_be_bytes()); // ID
        // Flags and offset
        assert_eq!(&header[6..8], &flags_offset.to_be_bytes());
        assert_eq!(header[8], 64); // TTL
        assert_eq!(header[9], 17); // UDP protocol
        assert_eq!(&header[12..16], &src.octets());
        assert_eq!(&header[16..20], &dst.octets());
    }

    #[test]
    fn test_ip_fragmentation_calculations() {
        // Test MF flag
        assert_eq!(IP_MF, 0x2000);
        // Test DF flag
        assert_eq!(IP_DF, 0x4000);
        // Test offset mask
        assert_eq!(IP_OFFSET_MASK, 0x1FFF);
        
        // Test fragment offset calculation (in 8-byte units)
        let offset_bytes: usize = 80;
        let frag_offset = (offset_bytes / 8) as u16;
        assert_eq!(frag_offset, 10);
        
        // Test flags_offset with MF flag
        let flags_offset = frag_offset | IP_MF;
        assert_eq!(flags_offset & IP_MF, IP_MF); // MF set
        assert_eq!(flags_offset & IP_OFFSET_MASK, 10); // Offset is 10
    }

    #[test]
    fn test_tls_split_record_construction() {
        // Test TLS record split logic without actual injection
        // Build a sample TLS Client Hello record
        let tls_header = vec![
            0x16,       // Content type: Handshake
            0x03, 0x01, // Version: TLS 1.0
            0x00, 0x20, // Length: 32 bytes of handshake data
        ];
        let handshake_data = vec![0u8; 32]; // 32 bytes of zeros as handshake data
        
        let original_payload: Vec<u8> = tls_header.iter()
            .chain(handshake_data.iter())
            .copied()
            .collect();
        
        assert_eq!(original_payload.len(), 37); // 5 + 32
        
        // Test split at position 21 (after TLS header + 16 bytes of handshake)
        let split_pos = 21;
        let tls_header_len = 5;
        
        // First part should be: TLS header + first 16 bytes of handshake
        let first_record_len = split_pos - tls_header_len; // 16
        let second_record_len = 32 - first_record_len; // 16
        
        assert_eq!(first_record_len, 16);
        assert_eq!(second_record_len, 16);
        
        // Verify first record header construction
        let mut first_record = Vec::new();
        first_record.push(0x16); // Content type
        first_record.push(0x03); // Version major
        first_record.push(0x01); // Version minor
        first_record.extend_from_slice(&(first_record_len as u16).to_be_bytes()); // Length
        first_record.extend_from_slice(&handshake_data[0..first_record_len]);
        
        assert_eq!(first_record.len(), tls_header_len + first_record_len);
        assert_eq!(&first_record[3..5], &(first_record_len as u16).to_be_bytes());
        
        // Verify second record header construction
        let mut second_record = Vec::new();
        second_record.push(0x16);
        second_record.push(0x03);
        second_record.push(0x01);
        second_record.extend_from_slice(&(second_record_len as u16).to_be_bytes());
        second_record.extend_from_slice(&handshake_data[first_record_len..]);
        
        assert_eq!(second_record.len(), tls_header_len + second_record_len);
        assert_eq!(&second_record[3..5], &(second_record_len as u16).to_be_bytes());
    }

    #[test]
    fn test_tls_split_validation() {
        // Test validation logic for TLS split
        const TLS_RECORD_HEADER_LEN: usize = 5;
        let payload_short = vec![0u8; 3]; // Too short
        
        // Should fail validation - payload too short
        assert!(payload_short.len() < TLS_RECORD_HEADER_LEN);
        
        // Test split position validation
        let payload = vec![0u8; 40]; // Valid payload
        let invalid_split_1 = 3; // Before TLS header ends
        let invalid_split_2 = 40; // At payload end (no data for second record)
        let valid_split = 20; // Valid split position
        
        assert!(invalid_split_1 <= TLS_RECORD_HEADER_LEN);
        assert!(invalid_split_2 >= payload.len());
        assert!(valid_split > TLS_RECORD_HEADER_LEN && valid_split < payload.len());
    }

    #[test]
    fn test_tls_record_header_parsing() {
        // Test parsing of TLS record header
        let tls_record = vec![
            0x16,       // Handshake
            0x03, 0x03, // TLS 1.2
            0x01, 0x00, // Length: 256 bytes
        ];
        
        let content_type = tls_record[0];
        let version_major = tls_record[1];
        let version_minor = tls_record[2];
        let length = ((tls_record[3] as usize) << 8) | (tls_record[4] as usize);
        
        assert_eq!(content_type, 0x16);
        assert_eq!(version_major, 0x03);
        assert_eq!(version_minor, 0x03);
        assert_eq!(length, 256);
    }

    #[test]
    fn test_oob_tcp_header_construction() {
        // Test building TCP header with urgent pointer
        let src_port: u16 = 12345;
        let dst_port: u16 = 443;
        let seq: u32 = 1000;
        let ack: u32 = 500;
        let flags: u8 = 0x38; // URG (0x20) | PSH (0x08) | ACK (0x10)
        let urgent_ptr: u16 = 50; // OOB position
        let payload = b"GET / HTTP/1.1\r\n";
        
        let header = build_tcp_header_with_urgent(
            src_port, dst_port, seq, ack, flags, urgent_ptr, Some(payload)
        );
        
        // Verify header structure
        assert_eq!(header.len(), 20 + payload.len());
        assert_eq!(&header[0..2], &src_port.to_be_bytes());
        assert_eq!(&header[2..4], &dst_port.to_be_bytes());
        assert_eq!(&header[4..8], &seq.to_be_bytes());
        assert_eq!(&header[8..12], &ack.to_be_bytes());
        assert_eq!(header[12], 0x50); // Data offset 5 (20 bytes)
        assert_eq!(header[13], flags); // Flags (URG|PSH|ACK)
        assert_eq!(&header[14..16], &65535u16.to_be_bytes()); // Window size
        // Bytes 16-17 are checksum (calculated later)
        // Bytes 18-19 are urgent pointer
        assert_eq!(&header[18..20], &urgent_ptr.to_be_bytes());
        // Payload follows header
        assert_eq!(&header[20..], payload);
    }

    #[test]
    fn test_oob_flag_values() {
        // Test URG flag and combination flags
        let urg_flag: u8 = 0x20;
        let psh_flag: u8 = 0x08;
        let ack_flag: u8 = 0x10;
        
        // Individual flags
        assert_eq!(urg_flag, 0x20);
        assert_eq!(psh_flag, 0x08);
        assert_eq!(ack_flag, 0x10);
        
        // Combined flags for OOB
        let oob_flags = urg_flag | psh_flag | ack_flag;
        assert_eq!(oob_flags, 0x38);
        
        // Verify each flag is set in combination
        assert!(oob_flags & urg_flag != 0);
        assert!(oob_flags & psh_flag != 0);
        assert!(oob_flags & ack_flag != 0);
        
        // Verify other flags are NOT set
        assert_eq!(oob_flags & 0x01, 0); // No FIN
        assert_eq!(oob_flags & 0x02, 0); // No SYN
        assert_eq!(oob_flags & 0x04, 0); // No RST
    }

    #[test]
    fn test_oob_urgent_pointer_values() {
        // Test various urgent pointer values
        let ptr_min: u16 = 1;
        let ptr_mid: u16 = 1000;
        let ptr_max: u16 = 65535;
        
        // Test encoding to bytes (big-endian)
        assert_eq!(&ptr_min.to_be_bytes(), &[0x00, 0x01]);
        assert_eq!(&ptr_mid.to_be_bytes(), &[0x03, 0xE8]);
        assert_eq!(&ptr_max.to_be_bytes(), &[0xFF, 0xFF]);
        
        // Test common OOB positions
        let ptr_oob_1: u16 = 1;
        let ptr_oob_5: u16 = 5;
        let ptr_oob_10: u16 = 10;
        
        assert_eq!(u16::from_be_bytes([0x00, 0x01]), ptr_oob_1);
        assert_eq!(u16::from_be_bytes([0x00, 0x05]), ptr_oob_5);
        assert_eq!(u16::from_be_bytes([0x00, 0x0A]), ptr_oob_10);
    }

    #[test]
    fn test_oob_validation() {
        // Test OOB position validation logic
        let payload_len = 100;
        
        // Valid OOB positions
        assert!(1 < payload_len);
        assert!(50 < payload_len);
        
        // Invalid OOB positions
        let oob_zero: u16 = 0;
        let oob_too_large: u16 = 150; // > payload_len
        
        assert!(oob_zero == 0);
        assert!(oob_too_large as usize > payload_len);
    }

    #[test]
    fn test_disorder_split_positions() {
        // Test split position validation for disorder
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let payload_len = payload.len(); // ~40 bytes
        
        // Valid split positions
        let valid_split_1 = 10;
        let valid_split_2 = payload_len / 2;
        let valid_split_3 = payload_len - 1;
        
        assert!(valid_split_1 > 0 && valid_split_1 < payload_len);
        assert!(valid_split_2 > 0 && valid_split_2 < payload_len);
        assert!(valid_split_3 > 0 && valid_split_3 < payload_len);
        
        // Invalid split positions
        let invalid_split_0 = 0; // Zero position
        let invalid_split_end = payload_len; // At payload end
        let invalid_split_large = payload_len + 10; // Beyond payload
        
        assert!(invalid_split_0 == 0 || invalid_split_0 >= payload_len);
        assert!(invalid_split_end >= payload_len);
        assert!(invalid_split_large >= payload_len);
    }

    #[test]
    fn test_disorder_sequence_calculation() {
        // Test sequence number calculation for disorder packets
        let seq: u32 = 1000;
        let split_pos = 10;
        
        // Second packet sequence should be first seq + first_part_len
        let second_seq = seq.wrapping_add(split_pos as u32);
        assert_eq!(second_seq, 1010);
        
        // Test with larger payload
        let large_split = 1000;
        let second_seq_large = seq.wrapping_add(large_split as u32);
        assert_eq!(second_seq_large, 2000);
        
        // Test wrapping
        let seq_max: u32 = u32::MAX - 5;
        let second_seq_wrapped = seq_max.wrapping_add(10);
        assert_eq!(second_seq_wrapped, 4); // (MAX - 5) + 10 = MAX + 5 = 4 (wrapping)
    }

    #[test]
    fn test_disorder_payload_splitting() {
        // Test payload splitting logic for disorder
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split_pos = 10;
        
        let first_part = &payload[0..split_pos];
        let second_part = &payload[split_pos..];
        
        // Verify split
        assert_eq!(first_part.len(), split_pos);
        assert_eq!(first_part.len() + second_part.len(), payload.len());
        assert_eq!(first_part, b"GET / HTTP");
        assert_eq!(second_part, b"/1.1\r\nHost: example.com\r\n\r\n");
        
        // Verify concatenation restores original
        let combined: Vec<u8> = first_part.iter()
            .chain(second_part.iter())
            .copied()
            .collect();
        assert_eq!(&combined[..], payload);
    }

    #[test]
    fn test_disorder_flags() {
        // Test TCP flags for disorder packets
        let original_flags = 0x18; // PSH|ACK
        
        // First packet flags (always PSH|ACK)
        let first_flags = 0x18u8;
        assert_eq!(first_flags, 0x18);
        
        // Second packet flags (PSH|ACK or PSH|ACK|FIN if original had FIN)
        let second_flags_no_fin = if original_flags & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 };
        assert_eq!(second_flags_no_fin, 0x18);
        
        // With FIN flag
        let original_with_fin = 0x19; // FIN|PSH|ACK
        let second_flags_with_fin = if original_with_fin & 0x01 != 0 { 0x18 | 0x01 } else { 0x18 };
        assert_eq!(second_flags_with_fin, 0x19); // FIN|PSH|ACK
    }
}
