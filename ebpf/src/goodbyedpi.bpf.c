/* SPDX-License-Identifier: GPL-2.0 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define ETH_HLEN 14
#define IP_HLEN 20
#define TCP_HLEN 20

/* Mark for packets from userspace (to avoid loops) */
#define USERSPACE_MARK 0xD0F

/* Коды возврата для Traffic Control (TC) */
#ifndef TC_ACT_OK
#define TC_ACT_OK      0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT    2
#endif
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC  -1
#endif
#ifndef TC_ACT_REDIRECT
#define TC_ACT_REDIRECT 7
#endif

/* Enable debug logging */
#define DEBUG_LOG 1

/* Helper for debug logging - uses newer bpf_printk API */
#define bpf_dbg_printk(fmt, ...)                           \
    ({                                                      \
        if (DEBUG_LOG)                                      \
            bpf_printk(fmt, ##__VA_ARGS__);                \
    })

/* Config structure shared with userspace */
struct config {
    __s32 split_pos;
    __s32 oob_pos;
    __s32 fake_offset;
    __s32 tlsrec_pos;
    __u8 auto_rst;
    __u8 auto_redirect;
    __u8 auto_ssl;
    __u8 ip_fragment;      /* Enable IP fragmentation for QUIC/UDP */
    __u16 frag_size;       /* Fragment size (0 = default 8 bytes) */
};

/* Default fragment size for QUIC */
#define DEFAULT_QUIC_FRAG_SIZE 8

/* Maximum payload size to send via ring buffer */
#define MAX_PAYLOAD_SIZE 64

/* GSO (Generic Segmentation Offload) bypass */
#define TCP_GSO_OFF 0x10000

/* Connection key - now with IPv6 support */
struct conn_key {
    __u32 src_ip[4];   /* IPv4 uses only [0], IPv6 uses all */
    __u32 dst_ip[4];
    __u16 src_port;
    __u16 dst_port;
    __u8 is_ipv6;      /* 0 = IPv4, 1 = IPv6 */
    __u8 proto;        /* IPPROTO_TCP or IPPROTO_UDP */
};

/* Connection state */
struct conn_state {
    __u8 stage;
    __u32 last_seq;
    __u32 last_ack;
    __u8 flags;
    __u64 timestamp;
};

/* Ring buffer event - supports both IPv4 and IPv6 */
struct event {
    __u32 type;
    __u32 src_ip[4];   /* IPv4: only [0] is used, IPv6: all 4 values (16 bytes) */
    __u32 dst_ip[4];   /* IPv4: only [0] is used, IPv6: all 4 values (16 bytes) */
    __u16 src_port;
    __u16 dst_port;
    __u32 seq;
    __u32 ack;
    __u8 flags;
    __u8 payload_len;  /* Actual payload length (may be larger than MAX_PAYLOAD_SIZE) */
    __u8 is_ipv6;      /* 0 = IPv4, 1 = IPv6 */
    __u8 sni_offset;   /* SNI hostname offset in payload (for TLS Client Hello) */
    __u8 sni_length;   /* SNI hostname length (for TLS Client Hello) */
    __u8 reserved;     /* Padding for alignment */
    __u8 payload[MAX_PAYLOAD_SIZE];  /* First MAX_PAYLOAD_SIZE bytes of packet payload */
};

enum {
    EVENT_FAKE_TRIGGERED = 1,
    EVENT_RST_DETECTED,
    EVENT_REDIRECT_DETECTED,
    EVENT_SSL_ERROR_DETECTED,
    EVENT_DISORDER_TRIGGERED,  /* Packet disorder triggered */
    EVENT_SPLIT_TRIGGERED,     /* TCP split triggered - userspace sends two packets */
    EVENT_TLSREC_TRIGGERED,    /* TLS record split triggered - split at SNI boundary */
    EVENT_QUIC_FRAGMENT_TRIGGERED, /* QUIC/UDP IP fragmentation triggered */
    EVENT_OOB_TRIGGERED,       /* OOB (Out-of-Band) triggered - URG flag injection */
};

enum {
    STAGE_INIT = 0,
    STAGE_SPLIT,
    STAGE_OOB,
    STAGE_FAKE_SENT,
    STAGE_TLSREC,
    STAGE_DISORDER,
};

/* TCP flags */
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_FIN 0x01

/* BPF Maps - pinned to share between egress and ingress */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key);
    __type(value, struct conn_state);
} conn_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* SNI cache for quick lookups */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  /* dst_ip */
    __type(value, __u8); /* has_sni */
} sni_cache SEC(".maps");

/* Statistics counters */
struct stats {
    __u64 packets_total;
    __u64 packets_tcp;
    __u64 packets_udp;
    __u64 packets_ipv6;
    __u64 packets_http;
    __u64 packets_tls;
    __u64 packets_quic;
    __u64 packets_modified;
    __u64 events_sent;
    __u64 errors;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} stats_map SEC(".maps");

static __always_inline struct config *get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline struct stats *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void update_stats_packet(struct stats *s, int is_tcp, int is_udp, int is_ipv6, int is_http, int is_tls, int is_quic)
{
    if (!s)
        return;
    __sync_fetch_and_add(&s->packets_total, 1);
    if (is_tcp)
        __sync_fetch_and_add(&s->packets_tcp, 1);
    if (is_udp)
        __sync_fetch_and_add(&s->packets_udp, 1);
    if (is_ipv6)
        __sync_fetch_and_add(&s->packets_ipv6, 1);
    if (is_http)
        __sync_fetch_and_add(&s->packets_http, 1);
    if (is_tls)
        __sync_fetch_and_add(&s->packets_tls, 1);
    if (is_quic)
        __sync_fetch_and_add(&s->packets_quic, 1);
}

static __always_inline void update_stats_modified(struct stats *s)
{
    if (s)
        __sync_fetch_and_add(&s->packets_modified, 1);
}

static __always_inline void update_stats_event(struct stats *s)
{
    if (s)
        __sync_fetch_and_add(&s->events_sent, 1);
}

static __always_inline void update_stats_error(struct stats *s)
{
    if (s)
        __sync_fetch_and_add(&s->errors, 1);
}

/* Helper to copy payload data into event structure using skb.
 * Returns the number of bytes actually copied (0 to MAX_PAYLOAD_SIZE).
 */
static __always_inline __u8 copy_payload_to_event_skb(struct __sk_buff *skb, struct event *e,
                                                       __u32 payload_offset, __u32 payload_len)
{
    /* Determine how many bytes to copy (min of actual length and MAX_PAYLOAD_SIZE) */
    __u32 copy_len = payload_len < MAX_PAYLOAD_SIZE ? payload_len : MAX_PAYLOAD_SIZE;

    bpf_dbg_printk("[GoodByeDPI] copy_payload: ENTER payload_offset=%u, payload_len=%u, copy_len=%u, skb_len=%u\n",
                   payload_offset, payload_len, copy_len, skb->len);

    /* Initialize payload buffer to zero */
    __builtin_memset(e->payload, 0, MAX_PAYLOAD_SIZE);
    
    /* Safely copy payload data using bpf_skb_load_bytes
     * Note: bpf_skb_load_bytes can read from paged/frags data (GSO/TSO)
     */
    if (copy_len > 0) {
        /* bpf_skb_load_bytes handles GSO/TSO frags automatically */
        int ret = bpf_skb_load_bytes(skb, payload_offset, e->payload, copy_len);
        if (ret < 0) {
            bpf_dbg_printk("[GoodByeDPI] copy_payload FAILED: ret=%d, offset=%u, len=%u\n",
                           ret, payload_offset, copy_len);
            return 0;
        }
        bpf_dbg_printk("[GoodByeDPI] copy_payload SUCCESS: copied %u bytes, first_byte=0x%02x\n",
                       copy_len, e->payload[0]);
    } else {
        bpf_dbg_printk("[GoodByeDPI] copy_payload: ZERO copy_len (payload_len=%u)\n", payload_len);
    }
    
    return (__u8)copy_len;
}

/* Parse IPv4 TCP packet - returns payload offset instead of pointer */
static __always_inline int parse_ipv4_tcp(struct __sk_buff *skb,
                                          struct iphdr **iph,
                                          struct tcphdr **tcph,
                                          __u32 *payload_offset,
                                          __u32 *payload_len)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse IP - check minimum packet size first */
    if (data + ETH_HLEN + sizeof(struct iphdr) > data_end)
        return -1;

    struct iphdr *ip = data + ETH_HLEN;

    if (ip->protocol != IPPROTO_TCP)
        return -1;

    /* Validate IP header length */
    __u32 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr) || ip_header_len > 60)
        return -1;

    /* Check that TCP header fits */
    if ((void *)ip + ip_header_len + sizeof(struct tcphdr) > data_end)
        return -1;

    /* Parse TCP */
    struct tcphdr *tcp = (void *)ip + ip_header_len;

    /* Validate TCP header length */
    __u32 tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < sizeof(struct tcphdr) || tcp_header_len > 60)
        return -1;

    /* Calculate payload offset as sum of headers */
    __u32 total_headers = ETH_HLEN + ip_header_len + tcp_header_len;
    *payload_offset = total_headers;
    
    /* Use actual packet length from data_end - data (handles GSO/TSO correctly) */
    __u32 packet_len = (__u32)(data_end - data);
    
    bpf_dbg_printk("[GoodByeDPI] IPv4 TCP parse: skb_len=%u, linear_len=%u, total_headers=%u\n", 
                   skb->len, packet_len, total_headers);
    
    /* For payload length calculation, use skb->len (includes frags) */
    /* For offset verification, use packet_len (linear data only) */
    if (*payload_offset > packet_len) {
        bpf_dbg_printk("[GoodByeDPI] IPv4 TCP parse: payload in frags, offset=%u > linear=%u\n", 
                       *payload_offset, packet_len);
        /* Continue - bpf_skb_load_bytes can read from frags */
    }

    /* Calculate payload length from skb->len (includes frags for GSO) */
    if (skb->len > total_headers)
        *payload_len = skb->len - total_headers;
    else
        *payload_len = 0;
    
    bpf_dbg_printk("[GoodByeDPI] IPv4 TCP parse: payload_offset=%u, payload_len=%u\n", 
                   *payload_offset, *payload_len);

    *iph = ip;
    *tcph = tcp;

    return 0;
}

/* Parse IPv6 TCP packet - returns payload offset instead of pointer */
static __always_inline int parse_ipv6_tcp(struct __sk_buff *skb,
                                          __u32 *payload_offset,
                                          __u32 *payload_len,
                                          struct conn_key *key)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse IPv6 header - check minimum packet size */
    if (data + ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end)
        return -1;

    struct ipv6hdr *ip6 = data + ETH_HLEN;

    if (ip6->nexthdr != IPPROTO_TCP)
        return -1;

    /* Parse TCP */
    struct tcphdr *tcp = (void *)ip6 + sizeof(struct ipv6hdr);

    /* Validate TCP header length */
    __u32 tcp_header_len = tcp->doff * 4;
    if (tcp_header_len < sizeof(struct tcphdr) || tcp_header_len > 60)
        return -1;

    /* Calculate payload offset as sum of headers */
    __u32 total_headers = ETH_HLEN + sizeof(struct ipv6hdr) + tcp_header_len;
    *payload_offset = total_headers;
    
    /* Use skb->len for payload length (includes frags for GSO) */
    /* Use data_end - data for linear portion check */
    __u32 linear_len = (__u32)(data_end - data);
    
    /* Verify payload offset is within bounds */
    if (*payload_offset > skb->len)
        return -1;

    /* Calculate payload length from skb->len (includes frags) */
    if (skb->len > total_headers)
        *payload_len = skb->len - total_headers;
    else
        *payload_len = 0;

    /* Fill key with IPv6 addresses */
    __builtin_memcpy(key->src_ip, &ip6->saddr, 16);
    __builtin_memcpy(key->dst_ip, &ip6->daddr, 16);

    return 0;
}

/* Parse IPv4 UDP packet (for QUIC) - returns payload offset instead of pointer */
static __always_inline int parse_ipv4_udp(struct __sk_buff *skb,
                                          struct iphdr **iph,
                                          struct udphdr **udph,
                                          __u32 *payload_offset,
                                          __u32 *payload_len)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse IP - check minimum packet size */
    if (data + ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return -1;

    struct iphdr *ip = data + ETH_HLEN;

    if (ip->protocol != IPPROTO_UDP)
        return -1;

    /* Validate IP header length */
    __u32 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr) || ip_header_len > 60)
        return -1;

    /* Parse UDP */
    struct udphdr *udp = (void *)ip + ip_header_len;

    /* BPF verifier needs explicit bounds check here */
    if ((void *)udp + sizeof(struct udphdr) > data_end)
        return -1;

    /* Validate UDP length */
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr))
        return -1;

    /* Calculate payload offset */
    __u32 udp_header_len = sizeof(struct udphdr);
    __u32 total_headers = ETH_HLEN + ip_header_len + udp_header_len;
    *payload_offset = total_headers;
    
    /* Verify offset is within bounds */
    if (*payload_offset > skb->len)
        return -1;
    
    /* Calculate payload length - clamp to skb->len (includes frags for GSO) */
    __u32 calc_payload_len = udp_len - udp_header_len;
    __u32 max_payload = (skb->len > *payload_offset) ? (skb->len - *payload_offset) : 0;
    *payload_len = calc_payload_len < max_payload ? calc_payload_len : max_payload;

    *iph = ip;
    *udph = udp;

    return 0;
}

/* Parse IPv6 UDP packet (for QUIC) - returns payload offset instead of pointer */
static __always_inline int parse_ipv6_udp(struct __sk_buff *skb,
                                          __u32 *payload_offset,
                                          __u32 *payload_len,
                                          struct conn_key *key)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse IPv6 header - check minimum packet size */
    if (data + ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end)
        return -1;

    struct ipv6hdr *ip6 = data + ETH_HLEN;

    if (ip6->nexthdr != IPPROTO_UDP)
        return -1;

    /* Parse UDP */
    struct udphdr *udp = (void *)ip6 + sizeof(struct ipv6hdr);

    /* Validate UDP length */
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr))
        return -1;

    /* Calculate payload offset */
    __u32 udp_header_len = sizeof(struct udphdr);
    __u32 total_headers = ETH_HLEN + sizeof(struct ipv6hdr) + udp_header_len;
    *payload_offset = total_headers;
    
    /* Verify offset is within bounds */
    if (*payload_offset > skb->len)
        return -1;
    
    /* Calculate payload length - clamp to skb->len (includes frags) */
    __u32 calc_payload_len = udp_len - udp_header_len;
    __u32 max_payload = (skb->len > *payload_offset) ? (skb->len - *payload_offset) : 0;
    *payload_len = calc_payload_len < max_payload ? calc_payload_len : max_payload;

    /* Fill key with IPv6 addresses */
    __builtin_memcpy(key->src_ip, &ip6->saddr, 16);
    __builtin_memcpy(key->dst_ip, &ip6->daddr, 16);

    return 0;
}

/* New versions using skb for TC eBPF - these are the correct implementations */
static __always_inline int is_tls_client_hello_skb(struct __sk_buff *skb, __u32 payload_offset, __u32 payload_len)
{
    if (payload_len < 6)
        return 0;

    __u8 buf[6];
    if (bpf_skb_load_bytes(skb, payload_offset, buf, 6) < 0) {
        bpf_dbg_printk("[GoodByeDPI] TLS check: failed to load bytes\n");
        return 0;
    }
    
    __u8 content_type = buf[0];
    __u16 version = ((__u16)buf[1] << 8) | buf[2];
    
    bpf_dbg_printk("[GoodByeDPI] TLS check: content_type=0x%02x version=0x%04x\n",
                   content_type, version);

    /* TLS record layer: content type 22 = Handshake */
    return (content_type == 0x16 && version >= 0x0301);
}

static __always_inline int is_http_request_skb(struct __sk_buff *skb, __u32 payload_offset, __u32 payload_len)
{
    if (payload_len < 4)
        return 0;

    __u8 buf[4];
    if (bpf_skb_load_bytes(skb, payload_offset, buf, 4) < 0) {
        bpf_dbg_printk("[GoodByeDPI] HTTP check: failed to load bytes\n");
        return 0;
    }
    
    /* Big endian word from bytes */
    __u32 word = ((__u32)buf[0] << 24) | ((__u32)buf[1] << 16) | 
                  ((__u32)buf[2] << 8) | ((__u32)buf[3]);
    
    bpf_dbg_printk("[GoodByeDPI] HTTP check: word=0x%08x\n", word);

    /* Check for common HTTP methods */
    return (word == 0x47455420 || /* "GET " */
            word == 0x504f5354 || /* "POST" */
            word == 0x48545450 || /* "HTTP" */
            word == 0x434f4e4e || /* "CONN" */
            word == 0x4f505449 || /* "OPTI" */
            word == 0x44454c45 || /* "DELE" */
            word == 0x48454144 || /* "HEAD" */
            word == 0x50555420);  /* "PUT " */
}

/* Check if payload looks like QUIC (simplified check) - skb version */
static __always_inline int is_quic_initial_skb(struct __sk_buff *skb, __u32 payload_offset, __u32 payload_len)
{
    if (payload_len < 4)
        return 0;

    __u8 first_byte;
    
    if (bpf_skb_load_bytes(skb, payload_offset, &first_byte, sizeof(first_byte)) < 0)
        return 0;

    /* QUIC Long Header: first bit is 1 (0x80 mask) */
    /* Version 1: 0x00 0x00 0x00 0x01 */
    if ((first_byte & 0x80) == 0)
        return 0;  /* Short header, not Initial */

    /* It's likely QUIC Initial if first bit is set */
    return 1;
}

/* TLS Constants */
#define TLS_HANDSHAKE           0x16
#define TLS_CLIENT_HELLO        0x01
#define TLS_SNI_EXTENSION       0x0000

/* Maximum iterations for loops (BPF verifier requirement) */
#define MAX_EXTENSIONS_ITER     32
#define MAX_SNI_LEN             253

/*
 * Parse TLS Client Hello and find SNI extension offset - skb version.
 *
 * TLS Record Layer (5 bytes):
 *   - content_type (1 byte): 0x16 = Handshake
 *   - version (2 bytes): TLS version
 *   - length (2 bytes): length of handshake data
 *
 * Handshake Layer:
 *   - type (1 byte): 0x01 = Client Hello
 *   - length (3 bytes): length of Client Hello
 *
 * Client Hello:
 *   - version (2 bytes)
 *   - random (32 bytes)
 *   - session_id_len (1 byte) + session_id (variable)
 *   - cipher_suites_len (2 bytes) + cipher_suites (variable)
 *   - compression_len (1 byte) + compression (variable)
 *   - extensions_len (2 bytes) + extensions (variable)
 *
 * Extension format:
 *   - type (2 bytes): 0x0000 = SNI
 *   - length (2 bytes)
 *   - data (variable)
 *
 * SNI extension data:
 *   - list_length (2 bytes)
 *   - name_type (1 byte): 0x00 = hostname
 *   - name_length (2 bytes)
 *   - name (variable)
 *
 * Returns: offset from payload start to SNI hostname, or negative on error
 */
static __always_inline int parse_tls_client_hello_sni_skb(struct __sk_buff *skb, __u32 payload_offset, 
                                                           __u32 payload_len,
                                                           __u32 *sni_offset, __u32 *sni_length)
{
    /* Need at least TLS record header + handshake header + client hello header */
    if (payload_len < 43)
        return -1;

    /* Read TLS Record Layer */
    __u8 content_type;
    __u16 tls_version;
    __u16 record_len;
    
    if (bpf_skb_load_bytes(skb, payload_offset, &content_type, 1) < 0)
        return -1;
    if (bpf_skb_load_bytes(skb, payload_offset + 1, &tls_version, 2) < 0)
        return -1;
    if (bpf_skb_load_bytes(skb, payload_offset + 3, &record_len, 2) < 0)
        return -1;
    
    tls_version = bpf_ntohs(tls_version);
    record_len = bpf_ntohs(record_len);
    
    /* Verify TLS Handshake */
    if (content_type != TLS_HANDSHAKE)
        return -1;
    
    /* Check record length is reasonable */
    if (record_len < 42 || record_len > 16384)
        return -1;
    
    /* Read Handshake Layer */
    __u8 handshake_type;
    __u32 handshake_len = 0;
    
    if (bpf_skb_load_bytes(skb, payload_offset + 5, &handshake_type, 1) < 0)
        return -1;
    
    /* Handshake length is 3 bytes (24-bit) */
    __u8 len_bytes[3];
    if (bpf_skb_load_bytes(skb, payload_offset + 6, len_bytes, 3) < 0)
        return -1;
    handshake_len = (len_bytes[0] << 16) | (len_bytes[1] << 8) | len_bytes[2];
    
    /* Verify Client Hello */
    if (handshake_type != TLS_CLIENT_HELLO)
        return -1;
    
    /* Start parsing Client Hello at offset 9 (after record header + handshake header) */
    __u32 offset = 9;
    
    /* Skip client version (2 bytes) */
    offset += 2;
    
    /* Skip random (32 bytes) */
    offset += 32;
    
    /* Skip session ID */
    if (offset + 1 > payload_len)
        return -1;
    __u8 session_id_len;
    if (bpf_skb_load_bytes(skb, payload_offset + offset, &session_id_len, 1) < 0)
        return -1;
    session_id_len &= 0x3F;
    offset += 1 + session_id_len;
    
    /* Skip cipher suites */
    if (offset + 2 > payload_len)
        return -1;
    __u16 cipher_suites_len;
    if (bpf_skb_load_bytes(skb, payload_offset + offset, &cipher_suites_len, 2) < 0)
        return -1;
    cipher_suites_len = bpf_ntohs(cipher_suites_len);
    /* Жесткая проверка на максимальный размер cipher suites (защита от вредоносных значений) */
    if (cipher_suites_len > 4096)
        return -1;
    offset += 2 + cipher_suites_len;
    
    /* Skip compression methods */
    if (offset + 1 > payload_len)
        return -1;
    __u8 compression_len;
    if (bpf_skb_load_bytes(skb, payload_offset + offset, &compression_len, 1) < 0)
        return -1;
    compression_len &= 0xFF;
    offset += 1 + compression_len;
    
    /* Now we're at extensions */
    if (offset + 2 > payload_len)
        return -1;
    
    __u16 extensions_len;
    if (bpf_skb_load_bytes(skb, payload_offset + offset, &extensions_len, 2) < 0)
        return -1;
    extensions_len = bpf_ntohs(extensions_len);
    offset += 2;
    
    /* Parse extensions to find SNI */
    __u32 extensions_end = offset + extensions_len;
    if (extensions_end > payload_len)
        extensions_end = payload_len;
    
    /* Loop through extensions (bounded for BPF verifier) */
    #pragma unroll
    for (int i = 0; i < MAX_EXTENSIONS_ITER; i++) {
        offset &= 0x3FFF;

        if (offset + 4 > extensions_end)
            break;
        
        __u16 ext_type;
        __u16 ext_len;
        
        if (bpf_skb_load_bytes(skb, payload_offset + offset, &ext_type, 2) < 0)
            break;
        if (bpf_skb_load_bytes(skb, payload_offset + offset + 2, &ext_len, 2) < 0)
            break;
        
        ext_type = bpf_ntohs(ext_type);
        ext_len = bpf_ntohs(ext_len);
        
        /* Found SNI extension (type 0x0000) */
        if (ext_type == TLS_SNI_EXTENSION) {
            __u32 sni_data_offset = offset + 4;  /* Start of extension data */
            
            if (sni_data_offset + 2 > extensions_end)
                break;
            
            /* SNI list length (2 bytes) */
            __u16 sni_list_len;
            if (bpf_skb_load_bytes(skb, payload_offset + sni_data_offset, &sni_list_len, 2) < 0)
                break;
            sni_list_len = bpf_ntohs(sni_list_len);
            
            /* SNI entry: name_type (1) + name_length (2) + name */
            __u32 sni_entry_offset = sni_data_offset + 2;
            
            if (sni_entry_offset + 3 > extensions_end)
                break;
            
            __u8 name_type;
            __u16 name_len;
            
            if (bpf_skb_load_bytes(skb, payload_offset + sni_entry_offset, &name_type, 1) < 0)
                break;
            if (bpf_skb_load_bytes(skb, payload_offset + sni_entry_offset + 1, &name_len, 2) < 0)
                break;
            name_len = bpf_ntohs(name_len);
            
            /* name_type 0x00 = hostname */
            if (name_type == 0x00 && name_len > 0 && name_len <= MAX_SNI_LEN) {
                __u32 hostname_offset = sni_entry_offset + 3;
                
                if (hostname_offset + name_len <= extensions_end) {
                    *sni_offset = hostname_offset;
                    *sni_length = name_len;
                    bpf_dbg_printk("[GoodByeDPI] SNI found at offset=%u, len=%u\n",
                                   hostname_offset, name_len);
                    return 0;  /* Success */
                }
            }
            
            break;  /* Found SNI extension, done */
        }
        
        /* Move to next extension */
        offset += 4 + ext_len;
    }
    
    return -1;  /* SNI not found */
}

/* Helper function to find SNI offset - skb version 
 * Note: This function requires skb context and is kept for API compatibility.
 * For new code, use parse_tls_client_hello_sni_skb directly.
 */
static __always_inline int find_sni_offset_skb(struct __sk_buff *skb, __u32 payload_offset, __u32 payload_len)
{
    __u32 sni_offset = 0;
    __u32 sni_length = 0;
    
    if (parse_tls_client_hello_sni_skb(skb, payload_offset, payload_len, &sni_offset, &sni_length) == 0) {
        return (__s32)sni_offset;
    }
    return -1;
}

/* Helper to safely read packet data */
static __always_inline int skb_read_bytes(struct __sk_buff *skb, __u32 offset, void *to, __u32 len)
{
    return bpf_skb_load_bytes(skb, offset, to, len);
}

/* Process TCP packet (IPv4 or IPv6) */
static __always_inline int process_tcp(struct __sk_buff *skb, struct config *cfg, struct stats *stats,
                                       struct iphdr *ip, struct tcphdr *tcp, __u32 payload_offset, __u32 payload_len,
                                       struct conn_key *key, int is_ipv6)
{
    update_stats_packet(stats, 1, 0, is_ipv6, 0, 0, 0);

    bpf_dbg_printk("[GoodByeDPI] process_tcp: ENTER sport=%u dport=%u payload_len=%u\n",
                   bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), payload_len);

    /* Only process outgoing packets with payload */
    if (payload_len == 0) {
        bpf_dbg_printk("[GoodByeDPI] process_tcp: EXIT - empty payload\n");
        return TC_ACT_OK;
    }

    bpf_dbg_printk("[GoodByeDPI] TCP packet: sport=%u dport=%u len=%u offset=%u\n",
                   bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), payload_len, payload_offset);

    /* Check for HTTP/HTTPS using skb functions */
    int is_http = is_http_request_skb(skb, payload_offset, payload_len);
    int is_tls = is_tls_client_hello_skb(skb, payload_offset, payload_len);
    
    if (is_http) {
        bpf_dbg_printk("[GoodByeDPI] HTTP detected: payload_len=%u\n", payload_len);
        update_stats_packet(stats, 1, 0, is_ipv6, 1, 0, 0);
    }
    if (is_tls) {
        bpf_dbg_printk("[GoodByeDPI] TLS detected: payload_len=%u\n", payload_len);
        update_stats_packet(stats, 1, 0, is_ipv6, 0, 1, 0);
    }
    
    if (!is_http && !is_tls)
        return TC_ACT_OK;

    bpf_dbg_printk("[GoodByeDPI] Processing TCP packet: sport=%u dport=%u ipv6=%d\n",
                   bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), is_ipv6);

    /* Build connection key for IPv4 */
    if (!is_ipv6 && ip) {
        key->src_ip[0] = ip->saddr;
        key->dst_ip[0] = ip->daddr;
        key->src_ip[1] = key->src_ip[2] = key->src_ip[3] = 0;
        key->dst_ip[1] = key->dst_ip[2] = key->dst_ip[3] = 0;
    }
    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);
    key->is_ipv6 = is_ipv6;
    key->proto = IPPROTO_TCP;

    /* Get or create connection state */
    struct conn_state *state = bpf_map_lookup_elem(&conn_map, key);
    if (!state) {
        struct conn_state new_state = {
            .stage = STAGE_INIT,
            .last_seq = bpf_ntohl(tcp->seq),
            .last_ack = bpf_ntohl(tcp->ack_seq),
            .timestamp = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conn_map, key, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&conn_map, key);
        if (!state)
            return TC_ACT_OK;
    }

    /* Apply DPI bypass techniques based on stage */
    
    bpf_dbg_printk("[GoodByeDPI] Checking techniques: split_pos=%d, stage=%d, payload_len=%u\n",
                   cfg->split_pos, state->stage, payload_len);
    
    /* Technique 1: Real TCP Split - drop original packet and send two parts from userspace */
    if (cfg->split_pos > 0 && state->stage == STAGE_INIT) {
        bpf_dbg_printk("[GoodByeDPI] SPLIT condition met: split_pos=%d < payload_len=%u\n",
                       cfg->split_pos, payload_len);
        if ((__u32)cfg->split_pos < payload_len) {
            bpf_dbg_printk("[GoodByeDPI] REAL SPLIT triggered at pos=%d, dropping packet\n", cfg->split_pos);
            state->stage = STAGE_SPLIT;
            update_stats_modified(stats);
            
            /* Send event to userspace to inject both split parts */
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e) {
                bpf_dbg_printk("[GoodByeDPI] FAILED to reserve ringbuf event!\n");
            }
            if (e) {
                e->type = EVENT_SPLIT_TRIGGERED;
                /* Copy IP addresses - full IPv6 support */
                e->src_ip[0] = key->src_ip[0];
                e->src_ip[1] = key->src_ip[1];
                e->src_ip[2] = key->src_ip[2];
                e->src_ip[3] = key->src_ip[3];
                e->dst_ip[0] = key->dst_ip[0];
                e->dst_ip[1] = key->dst_ip[1];
                e->dst_ip[2] = key->dst_ip[2];
                e->dst_ip[3] = key->dst_ip[3];
                e->src_port = key->src_port;
                e->dst_port = key->dst_port;
                e->seq = bpf_ntohl(tcp->seq);
                e->ack = bpf_ntohl(tcp->ack_seq);
                /* Store split position in flags field (lower byte) and TCP flags (upper byte) */
                e->flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3)) & 0x0F;
                e->reserved = (__u8)((cfg->split_pos > 255) ? 255 : cfg->split_pos);  /* Split position */
                e->is_ipv6 = is_ipv6;
                e->sni_offset = 0;
                e->sni_length = 0;
                /* Copy payload data using skb - payload_len is now actual copied bytes */
                e->payload_len = copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
                bpf_ringbuf_submit(e, 0);
                update_stats_event(stats);
                bpf_dbg_printk("[GoodByeDPI] SPLIT event sent to userspace (ipv6=%d, split_pos=%d)\n", is_ipv6, cfg->split_pos);
            }
            
            /* Update state and DROP the original packet - userspace will send split parts */
            bpf_map_update_elem(&conn_map, key, state, BPF_EXIST);
            return TC_ACT_SHOT;  /* Drop packet - userspace handles the split */
        }
    }

    /* Technique 2: OOB (Out of Band) - Set URG flag and urgent pointer */
    /* We drop the original packet and inject modified version from userspace */
    if (cfg->oob_pos > 0 && state->stage <= STAGE_SPLIT) {
        bpf_dbg_printk("[GoodByeDPI] OOB triggered at pos=%d\n", cfg->oob_pos);
        
        /* Only apply if payload is large enough */
        if ((__u32)cfg->oob_pos < payload_len) {
            /* Send event to userspace to inject OOB packet with URG flag */
            struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->type = EVENT_OOB_TRIGGERED;
                /* Copy IP addresses - full IPv6 support */
                e->src_ip[0] = key->src_ip[0];
                e->src_ip[1] = key->src_ip[1];
                e->src_ip[2] = key->src_ip[2];
                e->src_ip[3] = key->src_ip[3];
                e->dst_ip[0] = key->dst_ip[0];
                e->dst_ip[1] = key->dst_ip[1];
                e->dst_ip[2] = key->dst_ip[2];
                e->dst_ip[3] = key->dst_ip[3];
                e->src_port = key->src_port;
                e->dst_port = key->dst_port;
                e->seq = bpf_ntohl(tcp->seq);
                e->ack = bpf_ntohl(tcp->ack_seq);
                /* Store original TCP flags and OOB position */
                e->flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | 
                           (tcp->psh << 3) | (tcp->ack << 4) | TCP_FLAG_URG) & 0x3F;
                e->reserved = (__u8)((cfg->oob_pos > 255) ? 255 : cfg->oob_pos);  /* OOB position */
                e->is_ipv6 = is_ipv6;
                e->sni_offset = 0;
                e->sni_length = 0;
                /* Copy payload data using skb - payload_len is now actual copied bytes */
                e->payload_len = copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
                bpf_ringbuf_submit(e, 0);
                update_stats_event(stats);
                state->stage = STAGE_OOB;
                state->flags |= 0x01;  /* Mark OOB applied */
                update_stats_modified(stats);
                bpf_dbg_printk("[GoodByeDPI] OOB event sent to userspace (URG at pos=%d, ipv6=%d)\n",
                               cfg->oob_pos, is_ipv6);
            }
            
            /* Drop the original packet - userspace will send modified version with URG flag */
            bpf_map_update_elem(&conn_map, key, state, BPF_EXIST);
            return TC_ACT_SHOT;
        }
        
        state->stage = STAGE_OOB;
    }
    
    /* Technique 3: Fake Packet Injection - send fake packet before real data */
    /* This confuses DPI by sending a fake packet with different sequence number */
    if (cfg->fake_offset != 0 && state->stage <= STAGE_OOB) {
        bpf_dbg_printk("[GoodByeDPI] FAKE packet triggered, offset=%d\n", cfg->fake_offset);
        
        /* Send event to userspace to inject fake packet */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_FAKE_TRIGGERED;
            /* Copy IP addresses - full IPv6 support */
            e->src_ip[0] = key->src_ip[0];
            e->src_ip[1] = key->src_ip[1];
            e->src_ip[2] = key->src_ip[2];
            e->src_ip[3] = key->src_ip[3];
            e->dst_ip[0] = key->dst_ip[0];
            e->dst_ip[1] = key->dst_ip[1];
            e->dst_ip[2] = key->dst_ip[2];
            e->dst_ip[3] = key->dst_ip[3];
            e->src_port = key->src_port;
            e->dst_port = key->dst_port;
            e->seq = bpf_ntohl(tcp->seq);
            e->ack = bpf_ntohl(tcp->ack_seq);
            /* Store fake_offset in reserved field for userspace */
            /* flags byte 0 = TCP flags, bytes 1-2 reserved for future */
            e->flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3)) & 0x0F;
            e->reserved = 0;  /* Will be handled by userspace based on config */
            e->is_ipv6 = is_ipv6;
            e->sni_offset = 0;
            e->sni_length = 0;
            /* Copy payload data for potential fake packet content using skb */
            e->payload_len = copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
            bpf_ringbuf_submit(e, 0);
            update_stats_event(stats);
            state->stage = STAGE_FAKE_SENT;
            update_stats_modified(stats);
            bpf_dbg_printk("[GoodByeDPI] FAKE event sent to userspace (offset=%d, ipv6=%d)\n",
                           cfg->fake_offset, is_ipv6);
        }
    }
    
    /* Technique 4: Disorder - Reorder packets by modifying sequence numbers */
    /* This makes DPI think packets are out of order, potentially bypassing detection */
    /* Userspace will send second part of payload first, then first part */
    if (state->stage == STAGE_OOB || state->stage == STAGE_SPLIT) {
        /* CRITICAL FIX: Only apply disorder if we have payload to reorder */
        if (payload_len == 0) {
            bpf_dbg_printk("[GoodByeDPI] DISORDER: skipping - empty payload (stage=%d)\n", state->stage);
            /* Reset stage to avoid infinite loop */
            state->stage = STAGE_INIT;
            bpf_map_update_elem(&conn_map, key, state, BPF_EXIST);
            return TC_ACT_OK;
        }
        
        bpf_dbg_printk("[GoodByeDPI] DISORDER: triggering with payload_len=%u (stage=%d)\n",
                       payload_len, state->stage);
        
        /* Send event to userspace to trigger disorder logic */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_DISORDER_TRIGGERED;  /* Dedicated disorder event */
            /* Copy IP addresses - full IPv6 support */
            e->src_ip[0] = key->src_ip[0];
            e->src_ip[1] = key->src_ip[1];
            e->src_ip[2] = key->src_ip[2];
            e->src_ip[3] = key->src_ip[3];
            e->dst_ip[0] = key->dst_ip[0];
            e->dst_ip[1] = key->dst_ip[1];
            e->dst_ip[2] = key->dst_ip[2];
            e->dst_ip[3] = key->dst_ip[3];
            e->src_port = key->src_port;
            e->dst_port = key->dst_port;
            e->seq = bpf_ntohl(tcp->seq);
            e->ack = bpf_ntohl(tcp->ack_seq);
            /* Store original TCP flags */
            e->flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3)) & 0x0F;
            e->payload_len = payload_len > 255 ? 255 : payload_len;
            e->is_ipv6 = is_ipv6;
            e->sni_offset = 0;
            e->sni_length = 0;
            /* Store split position hint in reserved (0 = let userspace decide) */
            e->reserved = 0;
            /* Copy payload data using skb */
            copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
            bpf_ringbuf_submit(e, 0);
            update_stats_event(stats);
            state->stage = STAGE_DISORDER;
            update_stats_modified(stats);
            bpf_dbg_printk("[GoodByeDPI] DISORDER triggered, payload_len=%u\n", payload_len);
        }
        
        /* Drop the original packet - userspace will send disordered packets */
        bpf_map_update_elem(&conn_map, key, state, BPF_EXIST);
        return TC_ACT_SHOT;
    }

    /* Technique 5: TLS Record Split - Split TLS record at SNI boundary */
    /* This splits the TLS record itself (not TCP), making DPI see incomplete Client Hello */
    if (cfg->tlsrec_pos >= 0 && is_tls && state->stage == STAGE_INIT) {
        __u32 sni_off = 0;
        __u32 sni_len = 0;
        
        /* Parse TLS Client Hello to find SNI using skb */
        if (parse_tls_client_hello_sni_skb(skb, payload_offset, payload_len, &sni_off, &sni_len) == 0) {
            /* Calculate split position based on config:
             * - tlsrec_pos = 0: split at SNI start
             * - tlsrec_pos > 0: split at SNI start + tlsrec_pos (inside SNI)
             * - tlsrec_pos < 0: split at SNI end + tlsrec_pos (before SNI end)
             */
            __u32 split_at;
            if (cfg->tlsrec_pos == 0) {
                split_at = sni_off;
            } else if (cfg->tlsrec_pos > 0) {
                split_at = sni_off + cfg->tlsrec_pos;
                if (split_at > sni_off + sni_len)
                    split_at = sni_off + sni_len;
            } else {
                /* Negative offset from SNI end */
                __s32 neg_offset = -cfg->tlsrec_pos;
                if (neg_offset > (__s32)sni_len)
                    neg_offset = sni_len;
                split_at = sni_off + sni_len - neg_offset;
            }
            
            /* Ensure split position is valid */
            if (split_at > 0 && split_at < payload_len) {
                bpf_dbg_printk("[GoodByeDPI] TLSREC split at pos=%u (SNI at %u, len=%u)\n",
                               split_at, sni_off, sni_len);
                state->stage = STAGE_TLSREC;
                update_stats_modified(stats);
                
                struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
                if (e) {
                    e->type = EVENT_TLSREC_TRIGGERED;
                    /* Copy IP addresses - full IPv6 support */
                    e->src_ip[0] = key->src_ip[0];
                    e->src_ip[1] = key->src_ip[1];
                    e->src_ip[2] = key->src_ip[2];
                    e->src_ip[3] = key->src_ip[3];
                    e->dst_ip[0] = key->dst_ip[0];
                    e->dst_ip[1] = key->dst_ip[1];
                    e->dst_ip[2] = key->dst_ip[2];
                    e->dst_ip[3] = key->dst_ip[3];
                    e->src_port = key->src_port;
                    e->dst_port = key->dst_port;
                    e->seq = bpf_ntohl(tcp->seq);
                    e->ack = bpf_ntohl(tcp->ack_seq);
                    e->flags = (tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3)) & 0x0F;
                    e->is_ipv6 = is_ipv6;
                    /* Store SNI offset and length for userspace */
                    e->sni_offset = sni_off > 255 ? 255 : sni_off;
                    e->sni_length = sni_len > 255 ? 255 : sni_len;
                    /* Store split position in reserved field */
                    e->reserved = split_at > 255 ? 255 : split_at;
                    /* Copy payload data using skb */
                    e->payload_len = copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
                    bpf_ringbuf_submit(e, 0);
                    update_stats_event(stats);
                    bpf_dbg_printk("[GoodByeDPI] TLSREC event sent (split=%u, sni=%u:%u)\n",
                                   split_at, sni_off, sni_len);
                }
            }
        }
    }

    /* Update state in map */
    bpf_map_update_elem(&conn_map, key, state, BPF_EXIST);

    return TC_ACT_OK;
}

/* Process UDP packet (QUIC) for DPI bypass */
static __always_inline int process_udp(struct __sk_buff *skb, struct config *cfg, struct stats *stats,
                                       __u32 payload_offset, __u32 payload_len,
                                       struct conn_key *key, int is_ipv6,
                                       __u16 src_port, __u16 dst_port)
{
    bpf_dbg_printk("[GoodByeDPI] UDP packet: sport=%u dport=%u payload_len=%u ipv6=%d\n",
                   src_port, dst_port, payload_len, is_ipv6);
    
    /* Check if this looks like QUIC Initial packet using skb */
    int is_quic = is_quic_initial_skb(skb, payload_offset, payload_len);
    
    update_stats_packet(stats, 0, 1, is_ipv6, 0, 0, is_quic);

    if (!is_quic) {
        bpf_dbg_printk("[GoodByeDPI] UDP: not QUIC Initial (first_byte check failed)\n");
        return TC_ACT_OK;
    }

    /* Only process QUIC to port 443 (HTTPS/QUIC) */
    if (dst_port != 443 && src_port != 443) {
        bpf_dbg_printk("[GoodByeDPI] QUIC: port not 443, skipping (dport=%u)\n", dst_port);
        return TC_ACT_OK;
    }

    bpf_dbg_printk("[GoodByeDPI] QUIC detected: payload_len=%u ipv6=%d port=%u ip_fragment=%d frag_size=%u\n",
                   payload_len, is_ipv6, dst_port, cfg->ip_fragment, cfg->frag_size);

    key->src_port = src_port;
    key->dst_port = dst_port;
    key->is_ipv6 = is_ipv6;
    key->proto = IPPROTO_UDP;

    /* QUIC Fragmentation bypass technique */
    /* YouTube uses QUIC (HTTP/3), and DPI often fails to reassemble fragments */
    if (cfg->ip_fragment && payload_len > 20) {
        __u16 frag_size = cfg->frag_size > 0 ? cfg->frag_size : DEFAULT_QUIC_FRAG_SIZE;
        
        /* Send event to trigger IP fragmentation in userspace */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_QUIC_FRAGMENT_TRIGGERED;
            e->src_ip[0] = key->src_ip[0];
            e->src_ip[1] = key->src_ip[1];
            e->src_ip[2] = key->src_ip[2];
            e->src_ip[3] = key->src_ip[3];
            e->dst_ip[0] = key->dst_ip[0];
            e->dst_ip[1] = key->dst_ip[1];
            e->dst_ip[2] = key->dst_ip[2];
            e->dst_ip[3] = key->dst_ip[3];
            e->src_port = key->src_port;
            e->dst_port = key->dst_port;
            e->flags = 0;  /* No special flags needed - event type identifies this */
            e->is_ipv6 = is_ipv6;
            e->sni_offset = 0;
            e->sni_length = 0;
            e->reserved = frag_size > 255 ? 255 : (__u8)frag_size;
            /* Copy payload data using skb */
            e->payload_len = copy_payload_to_event_skb(skb, e, payload_offset, payload_len);
            bpf_ringbuf_submit(e, 0);
            update_stats_event(stats);
            bpf_dbg_printk("[GoodByeDPI] QUIC fragment triggered (size=%u)\n", frag_size);
        }
    }
    
    return TC_ACT_OK;
}

/* Main DPI logic - TC Egress */
SEC("tc/egress")
int dpi_egress(struct __sk_buff *skb)
{
    /* Skip packets marked by userspace (to avoid loops) */
    if (skb->mark == USERSPACE_MARK)
        return TC_ACT_OK;

    struct config *cfg = get_config();
    if (!cfg) {
        bpf_dbg_printk("[GoodByeDPI] No config found\n");
        return TC_ACT_OK;
    }

    struct stats *stats = get_stats();
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    bpf_dbg_printk("[GoodByeDPI] dpi_egress: ENTER, data_end-data=%u\n", 
                   (__u32)(data_end - data));

    /* Parse Ethernet */
    if (data + ETH_HLEN > data_end) {
        bpf_dbg_printk("[GoodByeDPI] dpi_egress: packet too small for eth\n");
        return TC_ACT_OK;
    }

    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    bpf_dbg_printk("[GoodByeDPI] dpi_egress: eth_proto=0x%04x\n", eth_proto);

    struct conn_key key = {};
    __u32 payload_offset = 0;
    __u32 payload_len = 0;
    int ret;

    /* Handle IPv4 */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = NULL;
        struct tcphdr *tcp = NULL;
        struct udphdr *udp = NULL;

        /* Try TCP first */
        ret = parse_ipv4_tcp(skb, &ip, &tcp, &payload_offset, &payload_len);
        bpf_dbg_printk("[GoodByeDPI] dpi_egress: parse_ipv4_tcp ret=%d\n", ret);
        if (ret == 0 && ip && tcp) {
            return process_tcp(skb, cfg, stats, ip, tcp, payload_offset, payload_len, &key, 0);
        }

        /* Try UDP (QUIC) */
        ret = parse_ipv4_udp(skb, &ip, &udp, &payload_offset, &payload_len);
        if (ret == 0 && ip && udp) {
            key.src_ip[0] = ip->saddr;
            key.dst_ip[0] = ip->daddr;
            return process_udp(skb, cfg, stats, payload_offset, payload_len, &key, 0,
                              bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
        }
    }
    /* Handle IPv6 */
    else if (eth_proto == ETH_P_IPV6) {
        struct tcphdr *tcp = NULL;
        struct udphdr *udp = NULL;

        /* Parse IPv6 header to get next header */
        struct ipv6hdr *ip6 = data + ETH_HLEN;
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return TC_ACT_OK;

        /* Use skb->len for payload length (includes frags for GSO) */

        /* Try TCP */
        if (ip6->nexthdr == IPPROTO_TCP) {
            tcp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return TC_ACT_OK;

            __u32 tcp_header_len = tcp->doff * 4;
            payload_offset = ETH_HLEN + sizeof(struct ipv6hdr) + tcp_header_len;
            
            /* Calculate payload length from skb->len */
            if (skb->len > payload_offset)
                payload_len = skb->len - payload_offset;
            else
                payload_len = 0;

            __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
            __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);

            return process_tcp(skb, cfg, stats, NULL, tcp, payload_offset, payload_len, &key, 1);
        }
        /* Try UDP (QUIC) */
        else if (ip6->nexthdr == IPPROTO_UDP) {
            udp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)udp + sizeof(*udp) > data_end)
                return TC_ACT_OK;

            __u32 udp_header_len = sizeof(struct udphdr);
            payload_offset = ETH_HLEN + sizeof(struct ipv6hdr) + udp_header_len;
            
            /* Calculate payload length from skb->len and UDP header */
            __u32 calc_payload_len = bpf_ntohs(udp->len) - udp_header_len;
            __u32 max_payload = (skb->len > payload_offset) ? (skb->len - payload_offset) : 0;
            payload_len = calc_payload_len < max_payload ? calc_payload_len : max_payload;

            __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
            __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);

            return process_udp(skb, cfg, stats, payload_offset, payload_len, &key, 1,
                              bpf_ntohs(udp->source), bpf_ntohs(udp->dest));
        }
    }

    return TC_ACT_OK;
}

/* Ingress detection for auto-logic - TC Ingress */
SEC("tc/ingress")
int dpi_ingress(struct __sk_buff *skb)
{
    /* Skip packets marked by userspace (to avoid loops) */
    if (skb->mark == USERSPACE_MARK)
        return TC_ACT_OK;

    struct config *cfg = get_config();
    if (!cfg)
        return TC_ACT_OK;

    /* Parse headers */
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet */
    if (data + ETH_HLEN > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    struct iphdr *ip = NULL;
    struct ipv6hdr *ip6 = NULL;
    struct tcphdr *tcp = NULL;
    __u32 payload_offset = 0;
    int is_ipv6 = 0;

    /* Handle IPv4 */
    if (eth_proto == ETH_P_IP) {
        ip = data + ETH_HLEN;
        if ((void *)ip + sizeof(*ip) > data_end)
            return TC_ACT_OK;

        if (ip->protocol != IPPROTO_TCP)
            return TC_ACT_OK;

        __u32 ip_header_len = ip->ihl * 4;
        tcp = (void *)ip + ip_header_len;
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;

        __u32 tcp_header_len = tcp->doff * 4;
        payload_offset = ETH_HLEN + ip_header_len + tcp_header_len;
    }
    /* Handle IPv6 */
    else if (eth_proto == ETH_P_IPV6) {
        ip6 = data + ETH_HLEN;
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return TC_ACT_OK;

        if (ip6->nexthdr != IPPROTO_TCP)
            return TC_ACT_OK;

        tcp = (void *)ip6 + sizeof(struct ipv6hdr);
        if ((void *)tcp + sizeof(*tcp) > data_end)
            return TC_ACT_OK;

        __u32 tcp_header_len = tcp->doff * 4;
        payload_offset = ETH_HLEN + sizeof(struct ipv6hdr) + tcp_header_len;
        is_ipv6 = 1;
    }
    else {
        return TC_ACT_OK;
    }

    /* Build reverse key for lookup */
    struct conn_key key = {};
    if (is_ipv6 && ip6) {
        __builtin_memcpy(key.src_ip, &ip6->daddr, 16);  /* swapped */
        __builtin_memcpy(key.dst_ip, &ip6->saddr, 16);  /* swapped */
    } else if (ip) {
        key.src_ip[0] = ip->daddr;   /* swapped */
        key.dst_ip[0] = ip->saddr;   /* swapped */
    }
    key.src_port = bpf_ntohs(tcp->dest);   /* swapped */
    key.dst_port = bpf_ntohs(tcp->source); /* swapped */
    key.is_ipv6 = is_ipv6;
    key.proto = IPPROTO_TCP;

    struct conn_state *state = bpf_map_lookup_elem(&conn_map, &key);
    if (!state)
        return TC_ACT_OK;

    /* Detect RST packets for auto-retry logic */
    if (tcp->rst && cfg->auto_rst) {
        bpf_dbg_printk("[GoodByeDPI] INGRESS: RST detected! sport=%u dport=%u\n",
                       bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_RST_DETECTED;
            /* Copy IP addresses - full IPv6 support */
            e->src_ip[0] = key.src_ip[0];
            e->src_ip[1] = key.src_ip[1];
            e->src_ip[2] = key.src_ip[2];
            e->src_ip[3] = key.src_ip[3];
            e->dst_ip[0] = key.dst_ip[0];
            e->dst_ip[1] = key.dst_ip[1];
            e->dst_ip[2] = key.dst_ip[2];
            e->dst_ip[3] = key.dst_ip[3];
            e->src_port = key.src_port;
            e->dst_port = key.dst_port;
            e->seq = bpf_ntohl(tcp->seq);
            e->ack = bpf_ntohl(tcp->ack_seq);
            e->flags = TCP_FLAG_RST;
            e->payload_len = 0;  /* RST packets typically have no payload */
            e->is_ipv6 = key.is_ipv6;
            e->sni_offset = 0;
            e->sni_length = 0;
            e->reserved = 0;
            /* Initialize payload to zero for RST */
            __builtin_memset(e->payload, 0, MAX_PAYLOAD_SIZE);
            bpf_ringbuf_submit(e, 0);
        }
    }

    /* Detect HTTP Redirect (302/301) for auto-logic */
    if (cfg->auto_redirect) {
        __u8 buf[MAX_PAYLOAD_SIZE];
        if (skb_read_bytes(skb, payload_offset, buf, sizeof(buf)) == 0) {
            if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
                /* Check for 302 or 301 */
                if (buf[9] == '3' && buf[10] == '0' && (buf[11] == '1' || buf[11] == '2')) {
                    bpf_dbg_printk("[GoodByeDPI] INGRESS: HTTP Redirect detected!\n");
                    struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
                    if (ev) {
                        ev->type = EVENT_REDIRECT_DETECTED;
                        /* Copy IP addresses - full IPv6 support */
                        ev->src_ip[0] = key.dst_ip[0];
                        ev->src_ip[1] = key.dst_ip[1];
                        ev->src_ip[2] = key.dst_ip[2];
                        ev->src_ip[3] = key.dst_ip[3];
                        ev->dst_ip[0] = key.src_ip[0];
                        ev->dst_ip[1] = key.src_ip[1];
                        ev->dst_ip[2] = key.src_ip[2];
                        ev->dst_ip[3] = key.src_ip[3];
                        ev->src_port = key.dst_port;
                        ev->dst_port = key.src_port;
                        ev->seq = bpf_ntohl(tcp->seq);
                        ev->ack = bpf_ntohl(tcp->ack_seq);
                        ev->flags = 0;
                        ev->payload_len = MAX_PAYLOAD_SIZE;
                        ev->is_ipv6 = key.is_ipv6;
                        ev->sni_offset = 0;
                        ev->sni_length = 0;
                        ev->reserved = 0;
                        /* Copy HTTP response payload */
                        __builtin_memset(ev->payload, 0, MAX_PAYLOAD_SIZE);
                        __builtin_memcpy(ev->payload, buf, MAX_PAYLOAD_SIZE);
                        bpf_ringbuf_submit(ev, 0);
                    }
                }
            }
        }
    }

    /* Detect SSL/TLS errors (alert level fatal) */
    if (cfg->auto_ssl) {
        __u8 buf[MAX_PAYLOAD_SIZE];
        if (skb_read_bytes(skb, payload_offset, buf, sizeof(buf)) == 0) {
            /* TLS alert: content type 0x15, alert level 0x02 = fatal */
            if (buf[0] == 0x15 && buf[5] == 0x02) {
                bpf_dbg_printk("[GoodByeDPI] INGRESS: SSL Fatal Alert detected!\n");
                struct event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
                if (ev) {
                    ev->type = EVENT_SSL_ERROR_DETECTED;
                    /* Copy IP addresses - full IPv6 support (swapped for response) */
                    ev->src_ip[0] = key.dst_ip[0];
                    ev->src_ip[1] = key.dst_ip[1];
                    ev->src_ip[2] = key.dst_ip[2];
                    ev->src_ip[3] = key.dst_ip[3];
                    ev->dst_ip[0] = key.src_ip[0];
                    ev->dst_ip[1] = key.src_ip[1];
                    ev->dst_ip[2] = key.src_ip[2];
                    ev->dst_ip[3] = key.src_ip[3];
                    ev->src_port = key.dst_port;
                    ev->dst_port = key.src_port;
                    ev->seq = bpf_ntohl(tcp->seq);
                    ev->ack = bpf_ntohl(tcp->ack_seq);
                    ev->flags = 0;
                    ev->payload_len = MAX_PAYLOAD_SIZE;
                    ev->is_ipv6 = key.is_ipv6;
                    ev->sni_offset = 0;
                    ev->sni_length = 0;
                    ev->reserved = 0;
                    /* Copy TLS alert payload */
                    __builtin_memset(ev->payload, 0, MAX_PAYLOAD_SIZE);
                    __builtin_memcpy(ev->payload, buf, MAX_PAYLOAD_SIZE);
                    bpf_ringbuf_submit(ev, 0);
                }
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
