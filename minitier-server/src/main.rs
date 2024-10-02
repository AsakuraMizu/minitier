use std::{collections::HashMap, fs, net::Ipv4Addr, sync::Arc};

use anyhow::Context;
use config::ExcludeConfig;
use etherparse::{NetSlice, SlicedPacket};
use ipnet::Ipv4Net;
use quinn::{Connection, Incoming, RecvStream};
use tokio::{
    select,
    sync::{mpsc, RwLock},
};
use tracing::{debug, info, instrument, Instrument, Span};

mod config;

struct Shared {
    conn_set: RwLock<HashMap<Ipv4Net, mpsc::UnboundedSender<Vec<u8>>>>,
    exclude: Vec<ExcludeConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = toml::from_str::<config::Config>(
        &fs::read_to_string("minitier-server.toml").context("Failed to read configuration file")?,
    )
    .context("Failed to parse configuration file")?;

    let shared = Arc::new(Shared {
        conn_set: RwLock::new(HashMap::new()),
        exclude: config.exclude,
    });

    let endpoint = config.server.bind().context("Failed to start server")?;
    info!("Listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        info!("Accepting connection");
        tokio::spawn(handle_connection(shared.clone(), incoming));
    }

    Ok(())
}

#[instrument(skip_all, fields(remote = %incoming.remote_address(), net), err)]
async fn handle_connection(shared: Arc<Shared>, incoming: Incoming) -> anyhow::Result<()> {
    let conn = incoming
        .await
        .context("Failed to accept incoming connection")?;
    info!("Connection established");

    let mut stream = conn.accept_uni().await?;
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await?;

    let [a, b, c, d, prefix_len] = buf;
    let net = Ipv4Net::new(Ipv4Addr::new(a, b, c, d), prefix_len)?;
    Span::current().record("net", tracing::field::display(&net));

    for i in shared.conn_set.read().await.keys() {
        if i.addr() == net.addr() {
            conn.close(1u8.into(), b"Duplicate IP address");
            anyhow::bail!("Duplicate IP address");
        }
    }

    let (tx, mut rx) = mpsc::unbounded_channel();
    shared.conn_set.write().await.insert(net, tx);
    drop(stream);
    info!("Added client");

    loop {
        select! {
            Some(data) = rx.recv() => {
                tokio::spawn(forward_to(conn.clone(), data).in_current_span());
            }
            Ok(stream) = conn.accept_uni() => {
                tokio::spawn(forward_from(shared.clone(), net, stream));
            }
            _ = conn.closed() => break,
            else => break,
        }
    }
    shared.conn_set.write().await.remove(&net);
    info!("Removed client");
    Ok(())
}

#[instrument(skip(shared, stream), err)]
async fn forward_from(
    shared: Arc<Shared>,
    src_net: Ipv4Net,
    mut stream: RecvStream,
) -> anyhow::Result<()> {
    let data = stream.read_to_end(u16::MAX as usize).await?;
    let pkt = SlicedPacket::from_ip(&data)?;
    if shared.exclude.iter().any(|e| e.check(&pkt)) {
        debug!("Excluding packet");
        return Ok(());
    }
    for (dest_net, tx) in shared.conn_set.read().await.iter() {
        if *dest_net == src_net {
            continue;
        }
        if let Some(NetSlice::Ipv4(ipv4)) = &pkt.net {
            let dest = ipv4.header().destination_addr();
            if dest.is_broadcast() || dest_net.addr() == dest || dest_net.broadcast() == dest {
                debug!(%dest, %dest_net, "Forwarding packet");
                tx.send(data.clone())?;
            }
        }
    }
    Ok(())
}

async fn forward_to(conn: Connection, data: Vec<u8>) -> anyhow::Result<()> {
    let mut stream = conn.open_uni().await?;
    stream.write_all(&data).await?;
    stream.finish()?;
    stream.stopped().await?;
    Ok(())
}
