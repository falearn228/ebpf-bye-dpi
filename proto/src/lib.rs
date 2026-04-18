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
///     bpf_printk: false,  // bpf_printk disabled by default
/// };
/// ```
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
    /// - `-1` = disabled
    /// - `0` = split at SNI start
    /// - positive value = split after SNI start
    /// - negative value (< -1) = split from SNI end
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
    /// Enable bpf_printk debug logs (writes into trace_pipe)
    pub bpf_printk: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            split_pos: 0,
            oob_pos: 0,
            fake_offset: 0,
            tlsrec_pos: -1,
            auto_rst: false,
            auto_redirect: false,
            auto_ssl: false,
            ip_fragment: 0,
            frag_size: 0,
            disorder: false,
            bpf_printk: false,
        }
    }
}

/// L4 protocol selector for rule engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProtocol {
    Tcp,
    Udp,
}

impl RuleProtocol {
    /// Parse protocol from CLI string (`tcp` or `udp`)
    pub fn from_cli(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Action selector for rule engine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Split,
    Oob,
    Fake,
    Tlsrec,
    Disorder,
    Frag,
}

impl RuleAction {
    /// Parse action from CLI string
    pub fn from_cli(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "split" => Some(Self::Split),
            "oob" => Some(Self::Oob),
            "fake" => Some(Self::Fake),
            "tlsrec" | "tls-split" => Some(Self::Tlsrec),
            "disorder" => Some(Self::Disorder),
            "frag" | "quic-frag" | "quic_frag" => Some(Self::Frag),
            _ => None,
        }
    }

    /// Default L4 protocol for action when rule protocol is omitted
    pub fn default_protocol(self) -> RuleProtocol {
        match self {
            Self::Frag => RuleProtocol::Udp,
            _ => RuleProtocol::Tcp,
        }
    }
}

/// Inclusive destination port range for rule matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// Rule engine item (zapret-like section)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub proto: RuleProtocol,
    pub ports: Vec<PortRange>,
    pub action: RuleAction,
    pub repeats: u8,
}

impl Rule {
    /// Match by protocol, destination port and action
    pub fn matches(&self, proto: RuleProtocol, dst_port: u16, action: RuleAction) -> bool {
        if self.proto != proto || self.action != action {
            return false;
        }

        if self.ports.is_empty() {
            return true;
        }

        self.ports.iter().any(|range| range.contains(dst_port))
    }
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
/// Packed to 40 bytes with explicit zeroed padding
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ConnKey {
    /// IPv4: only index 0 is used, rest are 0
    /// IPv6: all 4 u32 values (16 bytes total)
    pub src_ip: [u32; 4],
    pub dst_ip: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// 0 = IPv4, 1 = IPv6
    pub is_ipv6: u8,
    /// IPPROTO_TCP (6) or IPPROTO_UDP (17)
    pub proto: u8,
    /// Explicit padding - MUST be zeroed for consistent hashing
    pub _pad: [u8; 2],
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
    /// Positive server response detected for auto-logic success tracking
    pub const SUCCESS_DETECTED: u32 = 10;
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
///     _pad: [0; 3],
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
    /// Explicit padding to 4-byte alignment - MUST be zeroed
    pub _pad: [u8; 3],
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
            _pad: [0; 3],
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
        // eBPF copies raw IPv6 bytes into src_ip[4] via memcpy. Preserve native
        // in-memory byte layout of each u32 word to reconstruct original bytes.
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word = self.src_ip[i].to_ne_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        std::net::Ipv6Addr::from(bytes)
    }

    /// Get destination IP as Ipv6Addr (only valid if is_ipv6 == 1)
    pub fn dst_ip_v6(&self) -> std::net::Ipv6Addr {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let word = self.dst_ip[i].to_ne_bytes();
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word);
        }
        std::net::Ipv6Addr::from(bytes)
    }

    /// Format IP addresses for display
    pub fn format_ips(&self) -> (String, String) {
        if self.is_ipv6 != 0 {
            (
                format!("[{}]", self.src_ip_v6()),
                format!("[{}]", self.dst_ip_v6()),
            )
        } else {
            (self.src_ip_v4().to_string(), self.dst_ip_v4().to_string())
        }
    }
}

/// Connection state stored in BPF map
///
/// Tracks the processing state for each active connection.
/// Used to coordinate multi-stage bypass techniques.
///
/// Layout matches eBPF: timestamp(8) + last_seq(4) + last_ack(4) + stage(1) + flags(1) + reserved(6)
/// Total size: 24 bytes (aligned to 8 bytes due to u64)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnState {
    /// Timestamp of last activity (nanoseconds since boot)
    pub timestamp: u64,
    /// Last seen TCP sequence number
    pub last_seq: u32,
    /// Last seen TCP acknowledgment number
    pub last_ack: u32,
    /// Current processing stage - one of `stages::*`
    ///
    /// Stages:
    /// - `0` = INIT
    /// - `1` = SPLIT
    /// - `2` = OOB
    /// - `3` = FAKE_SENT
    /// - `4` = TLSREC
    pub stage: u8,
    /// Connection flags (reserved for future use)
    pub flags: u8,
    /// Reserved padding - must be zeroed for consistency (6 bytes to align to 24)
    pub _reserved: [u8; 6],
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

// Compile-time assertions to verify struct sizes match eBPF C code
#[cfg(test)]
mod size_tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_conn_key_size() {
        assert_eq!(
            std::mem::size_of::<ConnKey>(),
            40,
            "ConnKey must be 40 bytes"
        );
    }

    #[test]
    fn test_conn_state_size() {
        assert_eq!(
            std::mem::size_of::<ConnState>(),
            24,
            "ConnState must be 24 bytes (8-byte aligned)"
        );
    }

    #[test]
    fn test_config_size() {
        assert_eq!(std::mem::size_of::<Config>(), 24, "Config must be 24 bytes");
    }

    #[test]
    fn test_event_size() {
        assert_eq!(std::mem::size_of::<Event>(), 1084, "Event must be 1084 bytes (4 + 16 + 16 + 2 + 2 + 4 + 4 + 1 + 1 + 2 + 2 + 2 + 1 + 1024 = 1083, padded to 1084)");
    }

    #[test]
    fn test_stats_size() {
        assert_eq!(std::mem::size_of::<Stats>(), 80, "Stats must be 80 bytes");
    }

    #[test]
    fn test_conn_key_alignment() {
        assert_eq!(
            std::mem::align_of::<ConnKey>(),
            4,
            "ConnKey must be 4-byte aligned"
        );
    }

    #[test]
    fn test_conn_state_alignment() {
        assert_eq!(
            std::mem::align_of::<ConnState>(),
            8,
            "ConnState must be 8-byte aligned (due to u64 timestamp)"
        );
    }

    #[test]
    fn test_event_ipv6_conversion_roundtrip() {
        let src = Ipv6Addr::new(0xfd00, 0x0001, 0, 0, 0, 0, 0, 1).octets();
        let dst = Ipv6Addr::new(0xfd00, 0x0001, 0, 0, 0, 0, 0, 2).octets();

        let mut event = Event::default();
        event.is_ipv6 = 1;
        for i in 0..4 {
            event.src_ip[i] =
                u32::from_ne_bytes([src[i * 4], src[i * 4 + 1], src[i * 4 + 2], src[i * 4 + 3]]);
            event.dst_ip[i] =
                u32::from_ne_bytes([dst[i * 4], dst[i * 4 + 1], dst[i * 4 + 2], dst[i * 4 + 3]]);
        }

        assert_eq!(event.src_ip_v6(), Ipv6Addr::from(src));
        assert_eq!(event.dst_ip_v6(), Ipv6Addr::from(dst));
        assert_eq!(event.format_ips().0, "[fd00:1::1]");
        assert_eq!(event.format_ips().1, "[fd00:1::2]");
    }

    #[test]
    fn test_success_detected_event_type_is_stable() {
        assert_eq!(event_types::SUCCESS_DETECTED, 10);
    }
}
