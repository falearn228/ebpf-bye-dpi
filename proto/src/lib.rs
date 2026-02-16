//! Shared structures for eBPF <-> Userspace communication
//!
//! This module defines the data structures used for communication between
//! the eBPF kernel programs and the userspace daemon. All structures are
//! designed to match their C counterparts for binary compatibility.

/// Configuration structure shared between userspace and BPF kernel program
///
/// This struct controls the DPI (Deep Packet Inspection) bypass techniques
/// that will be applied to network traffic. It is passed from userspace
/// to the BPF program via a map.
///
/// # Example
/// ```
/// use goodbyedpi_proto::Config;
///
/// let config = Config {
///     split_pos: 10,      // Split HTTP requests at byte 10
///     oob_pos: 5,         // Insert OOB data at byte 5
///     fake_offset: -1,    // Fake packet offset
///     tlsrec_pos: 1,      // TLS record split position
///     auto_rst: true,     // Auto-detect RST packets
///     auto_redirect: false,
///     auto_ssl: false,
///     ip_fragment: 1,     // Enable IP fragmentation for QUIC
///     frag_size: 8,       // 8-byte fragments
///     disorder: false,    // Disable packet disorder
/// };
/// ```
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct Config {
    /// Split position for HTTP/TLS request fragmentation
    /// - `-1` or `0` = disabled
    /// - positive value = byte position to split at
    pub split_pos: i32,
    /// Out-of-band data insertion position
    /// - `-1` or `0` = disabled  
    /// - positive value = byte position for OOB marker
    pub oob_pos: i32,
    /// Fake packet offset for timing attacks
    /// - `0` = disabled
    /// - positive/negative = offset value
    pub fake_offset: i32,
    /// TLS record split position
    /// - `-1` or `0` = disabled
    /// - positive value = byte position to split TLS record
    pub tlsrec_pos: i32,
    /// Enable automatic RST packet detection and handling
    pub auto_rst: bool,
    /// Enable automatic HTTP redirect detection (301/302)
    pub auto_redirect: bool,
    /// Enable automatic SSL/TLS error detection
    pub auto_ssl: bool,
    /// Enable IP fragmentation for QUIC/UDP (0 = disabled, 1 = enabled)
    pub ip_fragment: u8,
    /// Fragment size for IP fragmentation (0 = default 8 bytes)
    pub frag_size: u16,
    /// Enable packet disorder technique (send packets out of order)
    pub disorder: bool,
}

/// Statistics counters from BPF
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub packets_total: u64,
    pub packets_tcp: u64,
    pub packets_udp: u64,
    pub packets_ipv6: u64,
    pub packets_http: u64,
    pub packets_tls: u64,
    pub packets_quic: u64,
    pub packets_modified: u64,
    pub events_sent: u64,
    pub errors: u64,
}

/// Connection key - supports both IPv4 and IPv6
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnKey {
    /// IPv4: only [0] is used, rest are 0
    /// IPv6: all 4 u32 values (16 bytes total)
    pub src_ip: [u32; 4],
    pub dst_ip: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// 0 = IPv4, 1 = IPv6
    pub is_ipv6: u8,
    /// IPPROTO_TCP (6) or IPPROTO_UDP (17)
    pub proto: u8,
}

/// Event types sent from BPF to userspace via ring buffer
///
/// These events notify the userspace daemon of significant
/// network events that may require action or logging.
pub mod event_types {
    /// Fake packet injection was triggered
    pub const FAKE_TRIGGERED: u32 = 1;
    /// RST packet was detected (connection reset)
    pub const RST_DETECTED: u32 = 2;
    /// HTTP redirect (301/302) was detected
    pub const REDIRECT_DETECTED: u32 = 3;
    /// SSL/TLS fatal alert was detected
    pub const SSL_ERROR_DETECTED: u32 = 4;
    /// Packet disorder was triggered
    pub const DISORDER_TRIGGERED: u32 = 5;
    /// TCP split was triggered - userspace should send two packets
    pub const SPLIT_TRIGGERED: u32 = 6;
    /// TLS record split was triggered - split at SNI boundary
    pub const TLSREC_TRIGGERED: u32 = 7;
    /// QUIC/UDP IP fragmentation triggered
    pub const QUIC_FRAGMENT_TRIGGERED: u32 = 8;
    /// OOB (Out-of-Band) triggered - URG flag injection
    pub const OOB_TRIGGERED: u32 = 9;
}

/// Connection processing stages
///
/// Tracks the current bypass technique stage for each connection.
pub mod stages {
    /// Initial state - no processing yet
    pub const INIT: u8 = 0;
    /// Request split has been applied
    pub const SPLIT: u8 = 1;
    /// Out-of-band data has been inserted
    pub const OOB: u8 = 2;
    /// Fake packet has been sent
    pub const FAKE_SENT: u8 = 3;
    /// TLS record split has been applied
    pub const TLSREC: u8 = 4;
    /// Packet disorder has been triggered
    pub const DISORDER: u8 = 5;
}

/// Maximum payload size that can be sent via ring buffer
/// 1024 bytes covers most TLS Client Hello (~200-600B) and partial QUIC Initial.
/// Limited by BPF stack size and verifier constraints on memset/memcpy.
pub const MAX_PAYLOAD_SIZE: usize = 1024;

/// Event from BPF ring buffer - supports both IPv4 and IPv6
///
/// Events are generated by the BPF program and sent to userspace
/// via a ring buffer map. They notify about detected conditions
/// such as blocked connections, redirects, or SSL errors.
///
/// # Example
/// ```
/// use goodbyedpi_proto::Event;
///
/// let event = Event {
///     event_type: 1,  // FAKE_TRIGGERED
///     src_ip: [192, 168, 1, 1].into(),
///     dst_ip: [10, 0, 0, 1].into(),
///     src_port: 54321,
///     dst_port: 443,
///     seq: 12345,
///     ack: 67890,
///     flags: 0x18,  // PSH|ACK
///     payload_len: 100,
///     is_ipv6: 0,
///     sni_offset: 0,
///     sni_length: 0,
///     reserved: 0,
///     payload: [0u8; 1024],
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Event {
    /// Event type - one of `event_types::*`
    ///
    /// Common values:
    /// - `1` = FAKE_TRIGGERED
    /// - `2` = RST_DETECTED
    /// - `3` = REDIRECT_DETECTED
    /// - `4` = SSL_ERROR_DETECTED
    /// - `6` = SPLIT_TRIGGERED
    /// - `7` = TLSREC_TRIGGERED
    pub event_type: u32,
    /// Source IP address
    /// - IPv4: only `[0]` is used (in network byte order)
    /// - IPv6: all 4 u32 values (16 bytes total)
    pub src_ip: [u32; 4],
    /// Destination IP address
    /// - IPv4: only `[0]` is used (in network byte order)
    /// - IPv6: all 4 u32 values (16 bytes total)
    pub dst_ip: [u32; 4],
    /// Source port (host byte order)
    pub src_port: u16,
    /// Destination port (host byte order)
    pub dst_port: u16,
    /// TCP sequence number
    pub seq: u32,
    /// TCP acknowledgment number
    pub ack: u32,
    /// TCP flags (FIN, SYN, RST, PSH, ACK, URG)
    pub flags: u8,
    /// IP version flag: `0` = IPv4, `1` = IPv6
    pub is_ipv6: u8,
    /// Payload length (actual length, may be larger than MAX_PAYLOAD_SIZE, clamped to 65535)
    pub payload_len: u16,
    /// SNI offset in payload (for TLS Client Hello)
    /// Contains the offset of the SNI hostname within the payload
    pub sni_offset: u16,
    /// SNI length (for TLS Client Hello)
    /// Contains the length of the SNI hostname
    pub sni_length: u16,
    /// Padding for alignment / reserved for future use
    pub reserved: u8,
    /// Payload data (first MAX_PAYLOAD_SIZE bytes of actual payload)
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

impl Default for Event {
    fn default() -> Self {
        Self {
            event_type: 0,
            src_ip: [0; 4],
            dst_ip: [0; 4],
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack: 0,
            flags: 0,
            is_ipv6: 0,
            payload_len: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0,
            payload: [0; MAX_PAYLOAD_SIZE],
        }
    }
}

impl Event {
    /// Get source IP as Ipv4Addr (only valid if is_ipv6 == 0)
    pub fn src_ip_v4(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.src_ip[0]))
    }

    /// Get destination IP as Ipv4Addr (only valid if is_ipv6 == 0)
    pub fn dst_ip_v4(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.dst_ip[0]))
    }

    /// Get source IP as Ipv6Addr (only valid if is_ipv6 == 1)
    pub fn src_ip_v6(&self) -> std::net::Ipv6Addr {
        let bytes: [u8; 16] = [
            (self.src_ip[0] >> 24) as u8, (self.src_ip[0] >> 16) as u8, 
            (self.src_ip[0] >> 8) as u8, self.src_ip[0] as u8,
            (self.src_ip[1] >> 24) as u8, (self.src_ip[1] >> 16) as u8,
            (self.src_ip[1] >> 8) as u8, self.src_ip[1] as u8,
            (self.src_ip[2] >> 24) as u8, (self.src_ip[2] >> 16) as u8,
            (self.src_ip[2] >> 8) as u8, self.src_ip[2] as u8,
            (self.src_ip[3] >> 24) as u8, (self.src_ip[3] >> 16) as u8,
            (self.src_ip[3] >> 8) as u8, self.src_ip[3] as u8,
        ];
        std::net::Ipv6Addr::from(bytes)
    }

    /// Get destination IP as Ipv6Addr (only valid if is_ipv6 == 1)
    pub fn dst_ip_v6(&self) -> std::net::Ipv6Addr {
        let bytes: [u8; 16] = [
            (self.dst_ip[0] >> 24) as u8, (self.dst_ip[0] >> 16) as u8,
            (self.dst_ip[0] >> 8) as u8, self.dst_ip[0] as u8,
            (self.dst_ip[1] >> 24) as u8, (self.dst_ip[1] >> 16) as u8,
            (self.dst_ip[1] >> 8) as u8, self.dst_ip[1] as u8,
            (self.dst_ip[2] >> 24) as u8, (self.dst_ip[2] >> 16) as u8,
            (self.dst_ip[2] >> 8) as u8, self.dst_ip[2] as u8,
            (self.dst_ip[3] >> 24) as u8, (self.dst_ip[3] >> 16) as u8,
            (self.dst_ip[3] >> 8) as u8, self.dst_ip[3] as u8,
        ];
        std::net::Ipv6Addr::from(bytes)
    }

    /// Format IP addresses for display
    pub fn format_ips(&self) -> (String, String) {
        if self.is_ipv6 != 0 {
            (format!("[{}]", self.src_ip_v6()), format!("[{}]", self.dst_ip_v6()))
        } else {
            (self.src_ip_v4().to_string(), self.dst_ip_v4().to_string())
        }
    }
}

/// Connection state stored in BPF map
///
/// Tracks the processing state for each active connection.
/// Used to coordinate multi-stage bypass techniques.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct ConnState {
    /// Current processing stage - one of `stages::*`
    /// 
    /// Stages:
    /// - `0` = INIT
    /// - `1` = SPLIT
    /// - `2` = OOB
    /// - `3` = FAKE_SENT
    /// - `4` = TLSREC
    pub stage: u8,
    /// Last seen TCP sequence number
    pub last_seq: u32,
    /// Last seen TCP acknowledgment number
    pub last_ack: u32,
    /// Connection flags (reserved for future use)
    pub flags: u8,
    /// Timestamp of last activity (nanoseconds since boot)
    pub timestamp: u64,
}

// Legacy constants - prefer using `stages::*` module

/// Initial state - no processing yet
pub const STAGE_INIT: u8 = 0;
/// Request split has been applied
pub const STAGE_SPLIT: u8 = 1;
/// Out-of-band data has been inserted
pub const STAGE_OOB: u8 = 2;
/// Fake packet has been sent
pub const STAGE_FAKE_SENT: u8 = 3;
/// TLS record split has been applied
pub const STAGE_TLSREC: u8 = 4;
/// Packet disorder has been triggered
pub const STAGE_DISORDER: u8 = 5;

/// Flag: Enable RST detection
pub const FLAG_AUTO_RST: u8 = 0x01;
/// Flag: Enable redirect detection  
pub const FLAG_AUTO_REDIRECT: u8 = 0x02;
/// Flag: Enable SSL error detection
pub const FLAG_AUTO_SSL: u8 = 0x04;
/// Flag: OOB (URG) was applied
pub const FLAG_OOB_APPLIED: u8 = 0x08;

/// Protocol number for TCP
pub const IPPROTO_TCP: u8 = 6;
/// Protocol number for UDP
pub const IPPROTO_UDP: u8 = 17;

/// Auto-logic strategy types for state machine
pub mod strategy_types {
    /// TCP split at specific position
    pub const TCP_SPLIT: u8 = 1;
    /// TLS record split
    pub const TLS_RECORD_SPLIT: u8 = 2;
    /// Out-of-order / Disorder
    pub const DISORDER: u8 = 3;
    /// Fake packet + split combination
    pub const FAKE_WITH_SPLIT: u8 = 4;
}

/// Auto-logic state machine state
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoLogicState {
    /// Current strategy type (strategy_types::*)
    pub strategy: u8,
    /// Current split position index or parameter
    pub param: u8,
    /// Current attempt count for this strategy
    pub attempts: u8,
    /// Flags: bit 0 = has_fake, bit 1 = has_disorder, etc.
    pub flags: u8,
    /// Reserved for future use
    pub reserved: [u8; 4],
}

impl AutoLogicState {
    /// Create new initial state
    pub fn new() -> Self {
        Self {
            strategy: strategy_types::TCP_SPLIT,
            param: 0,
            attempts: 0,
            flags: 0,
            reserved: [0; 4],
        }
    }

    /// Check if fake is enabled
    pub fn has_fake(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Enable fake flag
    pub fn enable_fake(&mut self) {
        self.flags |= 0x01;
    }

    /// Check if disorder is enabled
    pub fn has_disorder(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Enable disorder flag
    pub fn enable_disorder(&mut self) {
        self.flags |= 0x02;
    }

    /// Move to next strategy on RST
    pub fn next_strategy_on_rst(&mut self) {
        self.attempts += 1;
        match self.strategy {
            strategy_types::TCP_SPLIT => {
                // Try different split positions, then move to TLS
                if self.attempts >= 3 {
                    self.strategy = strategy_types::TLS_RECORD_SPLIT;
                    self.attempts = 0;
                }
            }
            strategy_types::TLS_RECORD_SPLIT => {
                // Move to disorder
                self.strategy = strategy_types::DISORDER;
                self.attempts = 0;
            }
            strategy_types::DISORDER => {
                // Cycle back to TCP split with increased param
                self.strategy = strategy_types::TCP_SPLIT;
                self.param = (self.param + 1) % 4;
                self.attempts = 0;
            }
            strategy_types::FAKE_WITH_SPLIT => {
                // Try different positions with fake
                if self.attempts >= 3 {
                    self.attempts = 0;
                    self.param = (self.param + 1) % 4;
                }
            }
            _ => {
                self.strategy = strategy_types::TCP_SPLIT;
            }
        }
    }

    /// Strengthen bypass on Redirect (add fake)
    pub fn strengthen_on_redirect(&mut self) {
        if !self.has_fake() {
            self.enable_fake();
            self.strategy = strategy_types::FAKE_WITH_SPLIT;
            self.attempts = 0;
        } else if !self.has_disorder() {
            // If already has fake, add disorder
            self.enable_disorder();
        }
    }

    /// Get current split position based on param
    pub fn get_split_position(&self) -> usize {
        // Try positions: 1, 2, 5, 10 based on param
        match self.param % 4 {
            0 => 1,
            1 => 2,
            2 => 5,
            _ => 10,
        }
    }
}
