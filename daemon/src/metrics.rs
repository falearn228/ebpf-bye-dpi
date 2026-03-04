use anyhow::{Context, Result};
use goodbyedpi_proto::Stats;
use log::{info, warn};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

pub async fn run_prometheus_server(bind_addr: String, stats: Arc<RwLock<Stats>>) -> Result<()> {
    let listener = TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind metrics server on {}", bind_addr))?;
    info!("Metrics endpoint listening on http://{}/metrics", bind_addr);

    loop {
        let (socket, _) = listener
            .accept()
            .await
            .context("Failed to accept metrics connection")?;
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, stats).await {
                warn!("Metrics request handling error: {}", e);
            }
        });
    }
}

async fn handle_connection(mut socket: TcpStream, stats: Arc<RwLock<Stats>>) -> Result<()> {
    let mut buffer = [0u8; 2048];
    let bytes_read = socket
        .read(&mut buffer)
        .await
        .context("Failed to read metrics request")?;
    if bytes_read == 0 {
        return Ok(());
    }

    let request = std::str::from_utf8(&buffer[..bytes_read]).unwrap_or("");
    let first_line = request.lines().next().unwrap_or("");

    if first_line.starts_with("GET /metrics ") {
        let snapshot = *stats.read().await;
        let body = format_prometheus_metrics(snapshot);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .context("Failed to write metrics response")?;
    } else {
        let body = "Not Found\n";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .context("Failed to write 404 response")?;
    }

    Ok(())
}

fn format_prometheus_metrics(s: Stats) -> String {
    format!(
        concat!(
            "# HELP goodbyedpi_packets_total Total packets processed by eBPF.\n",
            "# TYPE goodbyedpi_packets_total counter\n",
            "goodbyedpi_packets_total {}\n",
            "# HELP goodbyedpi_packets_tcp Total TCP packets processed.\n",
            "# TYPE goodbyedpi_packets_tcp counter\n",
            "goodbyedpi_packets_tcp {}\n",
            "# HELP goodbyedpi_packets_udp Total UDP packets processed.\n",
            "# TYPE goodbyedpi_packets_udp counter\n",
            "goodbyedpi_packets_udp {}\n",
            "# HELP goodbyedpi_packets_tls Total TLS packets detected.\n",
            "# TYPE goodbyedpi_packets_tls counter\n",
            "goodbyedpi_packets_tls {}\n",
            "# HELP goodbyedpi_packets_quic Total QUIC packets detected.\n",
            "# TYPE goodbyedpi_packets_quic counter\n",
            "goodbyedpi_packets_quic {}\n",
            "# HELP goodbyedpi_events_sent Total events sent from eBPF ring buffer.\n",
            "# TYPE goodbyedpi_events_sent counter\n",
            "goodbyedpi_events_sent {}\n",
            "# HELP goodbyedpi_errors Total internal eBPF errors.\n",
            "# TYPE goodbyedpi_errors counter\n",
            "goodbyedpi_errors {}\n",
            "# HELP goodbyedpi_packets_ipv6 Total IPv6 packets processed.\n",
            "# TYPE goodbyedpi_packets_ipv6 counter\n",
            "goodbyedpi_packets_ipv6 {}\n",
            "# HELP goodbyedpi_packets_http Total HTTP packets detected.\n",
            "# TYPE goodbyedpi_packets_http counter\n",
            "goodbyedpi_packets_http {}\n",
            "# HELP goodbyedpi_packets_modified Total packets modified by bypass logic.\n",
            "# TYPE goodbyedpi_packets_modified counter\n",
            "goodbyedpi_packets_modified {}\n"
        ),
        s.packets_total,
        s.packets_tcp,
        s.packets_udp,
        s.packets_tls,
        s.packets_quic,
        s.events_sent,
        s.errors,
        s.packets_ipv6,
        s.packets_http,
        s.packets_modified
    )
}
