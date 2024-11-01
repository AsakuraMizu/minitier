use std::fs;

use anyhow::Context;
use config::{IncomingRule, OutgoingRule};
use etherparse::{NetSlice, SlicedPacket};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use ipnet::Ipv4Net;
use iroh::{
    client::gossip::{SubscribeResponse, SubscribeUpdate},
    gossip::net::GossipEvent,
};
use tokio::{select, sync::mpsc};
use tracing::{debug, error, info, trace, warn};
use tun2::AsyncDevice;

mod config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = enable_ansi_support::enable_ansi_support();
    tracing_subscriber::fmt::init();

    let config = toml::from_str::<config::AppConfig>(
        &fs::read_to_string("minitier.toml").context("Failed to read configuration file")?,
    )
    .context("Failed to parse configuration file")?;

    let dev =
        tun2::create_as_async(&config.tun.configure()).context("Failed to create TUN device")?;

    let node = config.node.configure().await?.spawn().await?;
    info!("Node ID: {}", node.node_id());

    let (gossip_tx, gossip_rx) = node
        .gossip()
        .subscribe(config.net.topic, config.net.bootstrap)
        .await?;
    let (pkt_tx, pkt_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    tokio::spawn(gossip_eventloop(
        gossip_rx,
        pkt_tx,
        config.tun.addr,
        config.incoming,
    ));
    tokio::spawn(tun_eventloop(dev, pkt_rx, gossip_tx, config.outgoing));

    tokio::signal::ctrl_c().await?;
    node.shutdown().await
}

async fn gossip_eventloop(
    mut gossip_rx: impl Stream<Item = anyhow::Result<SubscribeResponse>> + Unpin,
    pkt_tx: mpsc::UnboundedSender<Vec<u8>>,
    addr: Ipv4Net,
    incoming: Vec<IncomingRule>,
) {
    while let Some(res) = gossip_rx.next().await {
        match res {
            Ok(ev) => match ev {
                SubscribeResponse::Lagged => warn!("Lagged"),
                SubscribeResponse::Gossip(ev) => match ev {
                    GossipEvent::Joined(peers) => {
                        info!("Joined network with {} peers", peers.len());
                        trace!(?peers);
                    }
                    GossipEvent::NeighborUp(peer) => trace!(?peer, "Neighbor came up"),
                    GossipEvent::NeighborDown(peer) => trace!(?peer, "Neighbor went down"),
                    GossipEvent::Received(msg) => {
                        trace!(?msg, "Received message");
                        let data = msg.content.to_vec();
                        let pkt = match SlicedPacket::from_ip(&data) {
                            Ok(pkt) => pkt,
                            Err(e) => {
                                debug!("Ignoring invalid incoming packet: {:?}", e);
                                return;
                            }
                        };
                        if let Some(NetSlice::Ipv4(ipv4)) = &pkt.net {
                            let dest = ipv4.header().destination_addr();
                            if dest.is_broadcast()
                                || addr.addr() == dest
                                || addr.broadcast() == dest
                            {
                                if incoming.iter().any(|rule| rule.allow(&pkt)) {
                                    let _ = pkt_tx.send(data);
                                } else {
                                    trace!("Dropping packet: no matching incoming rule found");
                                }
                            }
                        }
                    }
                },
            },
            Err(err) => error!("Failed to receive event: {:?}", err),
        }
    }
}

async fn tun_eventloop(
    dev: AsyncDevice,
    mut pkt_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    mut gossip_tx: impl Sink<SubscribeUpdate, Error = anyhow::Error> + Unpin,
    outgoing: Vec<OutgoingRule>,
) {
    let mut framed = dev.into_framed();
    loop {
        select! {
            res = framed.next() => match res.expect("TUN device exited?!") {
                Ok(data) => {
                    match SlicedPacket::from_ip(&data) {
                        Ok(pkt) => {
                            if outgoing.iter().any(|rule| rule.allow(&pkt)) {
                                if let Err(err) = gossip_tx.send(SubscribeUpdate::Broadcast(data.into())).await {
                                    error!("Failed to send packet: {:?}", err);
                                }
                            } else {
                                trace!("Dropping packet: no matching outgoing rule found");
                            }
                        }
                        Err(e) => debug!("Ignoring invalid outgoing packet: {:?}", e),
                    }
                }
                Err(err) => error!("Failed to read packet from TUN device: {:?}", err),
            },
            res = pkt_rx.recv() => {
                let Some(pkt) = res else {
                    break;
                };
                if let Err(err) = framed.send(pkt).await {
                    error!("Failed to write packet to TUN device: {:?}", err);
                }
            }
        }
    }
}
