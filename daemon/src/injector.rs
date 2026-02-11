use anyhow::{anyhow, Context, Result};
use log::debug;
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use std::net::Ipv4Addr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::RawFd;

/* Socket option for packet mark */
const SO_MARK: i32 = 36;

// TODO: field `sock` is never read
/// Raw socket injector for fake packets
pub struct RawInjector {
    sock: RawFd,
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

        Ok(Self { sock: raw_fd })
    }

    //TODO: methods `inject_fake_packet` and `raw_fd` are never used
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
    
    /// Get the raw socket file descriptor
    /// 
    /// # Safety
    /// The caller must ensure proper handling of the raw FD to avoid resource leaks
    pub fn raw_fd(&self) -> RawFd {
        self.sock
    }
}

// TODO: function `build_ip_header` is never used
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

// TODO: function `build_tcp_header` is never used
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


// TODO: function `calculate_checksum` is never used
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

// TODO: function `calculate_tcp_checksum` is never used
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
}
