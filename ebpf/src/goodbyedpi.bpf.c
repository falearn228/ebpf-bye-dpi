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
    __u8 payload_len;
    __u8 is_ipv6;      /* 0 = IPv4, 1 = IPv6 */
    __u8 reserved;     /* Padding for alignment */
};

enum {
    EVENT_FAKE_TRIGGERED = 1,
    EVENT_RST_DETECTED,
    EVENT_REDIRECT_DETECTED,
    EVENT_SSL_ERROR_DETECTED,
    EVENT_DISORDER_TRIGGERED,  /* New: Packet disorder triggered */
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

/* Parse IPv4 TCP packet */
static __always_inline int parse_ipv4_tcp(struct __sk_buff *skb,
                                          struct iphdr **iph,
                                          struct tcphdr **tcph,
                                          void **payload,
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

    /* Check payload pointer is within bounds */
    *payload = (void *)tcp + tcp_header_len;
    if (*payload > data_end)
        return -1;

    /* Calculate payload length safely */
    __u32 total_headers = ETH_HLEN + ip_header_len + tcp_header_len;
    if (skb->len > total_headers)
        *payload_len = skb->len - total_headers;
    else
        *payload_len = 0;

    *iph = ip;
    *tcph = tcp;

    return 0;
}

/* Parse IPv6 TCP packet */
static __always_inline int parse_ipv6_tcp(struct __sk_buff *skb,
                                          void **payload,
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

    /* Check payload pointer is within bounds */
    *payload = (void *)tcp + tcp_header_len;
    if (*payload > data_end)
        return -1;

    /* Calculate payload length safely */
    __u32 total_headers = ETH_HLEN + sizeof(struct ipv6hdr) + tcp_header_len;
    if (skb->len > total_headers)
        *payload_len = skb->len - total_headers;
    else
        *payload_len = 0;

    /* Fill key with IPv6 addresses */
    __builtin_memcpy(key->src_ip, &ip6->saddr, 16);
    __builtin_memcpy(key->dst_ip, &ip6->daddr, 16);

    return 0;
}

/* Parse IPv4 UDP packet (for QUIC) */
static __always_inline int parse_ipv4_udp(struct __sk_buff *skb,
                                          struct iphdr **iph,
                                          struct udphdr **udph,
                                          void **payload,
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

    /* Validate UDP length */
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(struct udphdr))
        return -1;

    /* Calculate payload - clamp to packet bounds */
    __u32 udp_header_len = sizeof(struct udphdr);
    *payload = (void *)udp + udp_header_len;
    
    __u32 calc_payload_len = udp_len - udp_header_len;
    __u32 max_payload = (__u32)(data_end - *payload);
    *payload_len = calc_payload_len < max_payload ? calc_payload_len : max_payload;

    *iph = ip;
    *udph = udp;

    return 0;
}

/* Parse IPv6 UDP packet (for QUIC) */
static __always_inline int parse_ipv6_udp(struct __sk_buff *skb,
                                          void **payload,
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

    /* Calculate payload - clamp to packet bounds */
    __u32 udp_header_len = sizeof(struct udphdr);
    *payload = (void *)udp + udp_header_len;
    
    __u32 calc_payload_len = udp_len - udp_header_len;
    __u32 max_payload = (__u32)(data_end - *payload);
    *payload_len = calc_payload_len < max_payload ? calc_payload_len : max_payload;

    /* Fill key with IPv6 addresses */
    __builtin_memcpy(key->src_ip, &ip6->saddr, 16);
    __builtin_memcpy(key->dst_ip, &ip6->daddr, 16);

    return 0;
}

/* Check if payload looks like TLS Client Hello */
static __always_inline int is_tls_client_hello(void *payload, __u32 payload_len)
{
    if (payload_len < 6)
        return 0;

    __u8 *data = payload;
    __u8 content_type;
    __u16 version;
    
    if (bpf_probe_read_kernel(&content_type, sizeof(content_type), data) < 0)
        return 0;
    if (bpf_probe_read_kernel(&version, sizeof(version), data + 1) < 0)
        return 0;

    /* TLS record layer: content type 22 = Handshake */
    return (content_type == 0x16 && bpf_ntohs(version) >= 0x0301);
}

/* Check if payload is HTTP request */
static __always_inline int is_http_request(void *payload, __u32 payload_len)
{
    if (payload_len < 4)
        return 0;

    __u8 *data = payload;
    __u32 word;
    
    if (bpf_probe_read_kernel(&word, sizeof(word), data) < 0)
        return 0;

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

/* Check if payload looks like QUIC (simplified check) */
static __always_inline int is_quic_initial(void *payload, __u32 payload_len)
{
    if (payload_len < 4)
        return 0;

    __u8 *data = payload;
    __u8 first_byte;
    
    if (bpf_probe_read_kernel(&first_byte, sizeof(first_byte), data) < 0)
        return 0;

    /* QUIC Long Header: first bit is 1 (0x80 mask) */
    /* Version 1: 0x00 0x00 0x00 0x01 */
    if ((first_byte & 0x80) == 0)
        return 0;  /* Short header, not Initial */

    /* Check for QUIC version (Q046, Q050, T050, T051, 1, etc) */
    __u32 version;
    if (bpf_probe_read_kernel(&version, sizeof(version), data) < 0)
        return 0;
    
    /* Common QUIC versions in network byte order */
    /* We just check if it's likely QUIC by the first byte pattern */
    return 1;
}

/* Find SNI offset in TLS Client Hello */
static __always_inline int find_sni_offset(void *payload, __u32 payload_len)
{
    if (payload_len < 43)
        return -1;

    /* SNI typically starts around byte 43-46 in TLS 1.2/1.3 Client Hello */
    /* This is a simplified check - real SNI parsing is more complex */
    return 43;
}

/* Helper to safely read packet data */
static __always_inline int skb_read_bytes(struct __sk_buff *skb, __u32 offset, void *to, __u32 len)
{
    return bpf_skb_load_bytes(skb, offset, to, len);
}

/* Process TCP packet (IPv4 or IPv6) */
static __always_inline int process_tcp(struct __sk_buff *skb, struct config *cfg, struct stats *stats,
                                       struct iphdr *ip, struct tcphdr *tcp, void *payload, __u32 payload_len,
                                       struct conn_key *key, int is_ipv6)
{
    update_stats_packet(stats, 1, 0, is_ipv6, 0, 0, 0);

    /* Only process outgoing packets with payload */
    if (payload_len == 0)
        return TC_ACT_OK;

    /* Check for HTTP/HTTPS */
    int is_http = is_http_request(payload, payload_len);
    int is_tls = is_tls_client_hello(payload, payload_len);
    
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
    
    /* Technique 1: Split the request */
    if (cfg->split_pos > 0 && state->stage == STAGE_INIT) {
        if ((__u32)cfg->split_pos < payload_len) {
            bpf_dbg_printk("[GoodByeDPI] SPLIT triggered at pos=%d\n", cfg->split_pos);
            state->stage = STAGE_SPLIT;
            update_stats_modified(stats);
            
            /* Send event to userspace to inject fake/second part */
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
                e->flags = tcp->fin | (tcp->syn << 1) | (tcp->rst << 2) | (tcp->psh << 3);
                e->payload_len = payload_len > 255 ? 255 : payload_len;
                e->is_ipv6 = is_ipv6;
                e->reserved = 0;
                bpf_ringbuf_submit(e, 0);
                update_stats_event(stats);
                bpf_dbg_printk("[GoodByeDPI] Event sent to userspace (ipv6=%d)\n", is_ipv6);
            }
        }
    }

    /* Technique 2: OOB (Out of Band) - Set URG flag and urgent pointer */
    if (cfg->oob_pos > 0 && state->stage <= STAGE_SPLIT) {
        bpf_dbg_printk("[GoodByeDPI] OOB triggered at pos=%d\n", cfg->oob_pos);
        
        /* Only apply if payload is large enough */
        if ((__u32)cfg->oob_pos < payload_len) {
            /* Modify TCP header in place - set URG flag and urgent pointer */
            __u8 tcp_flags = tcp->urg | TCP_FLAG_URG;  /* Set URG bit */
            __u16 urg_ptr = bpf_htons((__u16)cfg->oob_pos);
            
            /* Update TCP flags using bpf_skb_store_bytes */
            /* TCP flags are at offset 13 from start of TCP header */
            /* URG pointer is at offset 18-19 */
            
            /* We can't directly modify tcp->urg in TC, so we use skb modification */
            /* For TC egress, we can use bpf_skb_store_bytes if we have the offset */
            
            /* Note: Direct packet modification in TC requires careful bounds checking */
            /* For this implementation, we mark the connection state and let userspace handle 
             * the actual packet modification via packet injection */
            
            state->flags |= 0x01;  /* Mark OOB applied */
            update_stats_modified(stats);
            bpf_dbg_printk("[GoodByeDPI] OOB marked (URG at pos=%d)\n", cfg->oob_pos);
        }
        
        state->stage = STAGE_OOB;
    }
    
    /* Technique 4: Disorder - Reorder packets by modifying sequence numbers */
    /* This makes DPI think packets are out of order, potentially bypassing detection */
    if (state->stage == STAGE_OOB || state->stage == STAGE_SPLIT) {
        /* Randomly swap sequence numbers for some packets to create disorder */
        /* In practice, this would require more complex logic with packet buffering */
        /* For now, we mark the intent and let userspace handle complex reordering */
        
        /* Send event to userspace to trigger disorder logic */
        struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->type = EVENT_FAKE_TRIGGERED;  /* Reuse fake trigger with disorder flag */
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
            e->flags = 0xFE;  /* Special flag for DISORDER */
            e->is_ipv6 = is_ipv6;
            e->reserved = 0;
            bpf_ringbuf_submit(e, 0);
            update_stats_event(stats);
            state->stage = STAGE_DISORDER;
            update_stats_modified(stats);
            bpf_dbg_printk("[GoodByeDPI] DISORDER triggered\n");
        }
    }

    /* Technique 3: TLS Record Split */
    if (cfg->tlsrec_pos >= 0 && is_tls) {
        int sni_offset = find_sni_offset(payload, payload_len);
        if (sni_offset > 0 && (__u32)cfg->tlsrec_pos < payload_len) {
            int split_at = cfg->tlsrec_pos;
            if (split_at > 0 && (__u32)split_at < payload_len) {
                bpf_dbg_printk("[GoodByeDPI] TLSREC split at pos=%d\n", split_at);
                state->stage = STAGE_TLSREC;
                update_stats_modified(stats);
                
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
                    e->flags = 0xFF; /* Special flag for TLS split */
                    e->is_ipv6 = is_ipv6;
                    e->reserved = 0;
                    bpf_ringbuf_submit(e, 0);
                    update_stats_event(stats);
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
                                       void *payload, __u32 payload_len,
                                       struct conn_key *key, int is_ipv6,
                                       __u16 src_port, __u16 dst_port)
{
    /* Check if this looks like QUIC Initial packet */
    int is_quic = is_quic_initial(payload, payload_len);
    
    update_stats_packet(stats, 0, 1, is_ipv6, 0, 0, is_quic);

    if (!is_quic)
        return TC_ACT_OK;

    /* Only process QUIC to port 443 (HTTPS/QUIC) */
    if (dst_port != 443 && src_port != 443)
        return TC_ACT_OK;

    bpf_dbg_printk("[GoodByeDPI] QUIC detected: payload_len=%u ipv6=%d port=%u frag=%d\n", 
                   payload_len, is_ipv6, dst_port, cfg->ip_fragment);

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
            e->type = EVENT_FAKE_TRIGGERED;
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
            e->flags = 0xFD;  /* Special flag for QUIC fragmentation */
            e->payload_len = frag_size > 255 ? 255 : (__u8)frag_size;
            e->is_ipv6 = is_ipv6;
            e->reserved = 0;
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

    /* Parse Ethernet */
    if (data + ETH_HLEN > data_end)
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    struct conn_key key = {};
    void *payload = NULL;
    __u32 payload_len = 0;
    int ret;

    /* Handle IPv4 */
    if (eth_proto == ETH_P_IP) {
        struct iphdr *ip = NULL;
        struct tcphdr *tcp = NULL;
        struct udphdr *udp = NULL;

        /* Try TCP first */
        ret = parse_ipv4_tcp(skb, &ip, &tcp, &payload, &payload_len);
        if (ret == 0 && ip && tcp) {
            return process_tcp(skb, cfg, stats, ip, tcp, payload, payload_len, &key, 0);
        }

        /* Try UDP (QUIC) */
        ret = parse_ipv4_udp(skb, &ip, &udp, &payload, &payload_len);
        if (ret == 0 && ip && udp) {
            key.src_ip[0] = ip->saddr;
            key.dst_ip[0] = ip->daddr;
            return process_udp(skb, cfg, stats, payload, payload_len, &key, 0,
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

        /* Try TCP */
        if (ip6->nexthdr == IPPROTO_TCP) {
            tcp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return TC_ACT_OK;

            __u32 tcp_header_len = tcp->doff * 4;
            payload = (void *)tcp + tcp_header_len;
            payload_len = skb->len - ETH_HLEN - sizeof(struct ipv6hdr) - tcp_header_len;

            __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
            __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);

            return process_tcp(skb, cfg, stats, NULL, tcp, payload, payload_len, &key, 1);
        }
        /* Try UDP (QUIC) */
        else if (ip6->nexthdr == IPPROTO_UDP) {
            udp = (void *)ip6 + sizeof(struct ipv6hdr);
            if ((void *)udp + sizeof(*udp) > data_end)
                return TC_ACT_OK;

            __u32 udp_header_len = sizeof(struct udphdr);
            payload = (void *)udp + udp_header_len;
            payload_len = bpf_ntohs(udp->len) - udp_header_len;

            __builtin_memcpy(key.src_ip, &ip6->saddr, 16);
            __builtin_memcpy(key.dst_ip, &ip6->daddr, 16);

            return process_udp(skb, cfg, stats, payload, payload_len, &key, 1,
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
            e->is_ipv6 = key.is_ipv6;
            e->reserved = 0;
            bpf_ringbuf_submit(e, 0);
        }
    }

    /* Detect HTTP Redirect (302/301) for auto-logic */
    if (cfg->auto_redirect) {
        __u8 buf[12];
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
                        ev->is_ipv6 = key.is_ipv6;
                        ev->reserved = 0;
                        bpf_ringbuf_submit(ev, 0);
                    }
                }
            }
        }
    }

    /* Detect SSL/TLS errors (alert level fatal) */
    if (cfg->auto_ssl) {
        __u8 buf[6];
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
                    ev->is_ipv6 = key.is_ipv6;
                    ev->reserved = 0;
                    bpf_ringbuf_submit(ev, 0);
                }
            }
        }
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
