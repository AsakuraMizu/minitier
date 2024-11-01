use std::{collections::BTreeSet, path::PathBuf};

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use ipnet::Ipv4Net;
use iroh::{
    blobs::store::fs::Store,
    gossip::proto::TopicId,
    net::{
        endpoint::{default_relay_mode, TransportConfig},
        relay::{RelayMap, RelayMode, RelayNode},
        NodeId,
    },
    node::{Node, ProtocolBuilder},
};
use serde::{Deserialize, Deserializer};
use serde_with::{serde_as, DisplayFromStr};

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub node: NodeConfig,
    pub tun: TunConfig,
    pub net: NetConfig,
    pub incoming: Vec<IncomingRule>,
    pub outgoing: Vec<OutgoingRule>,
}

fn deserialize_relay_mode<'de, D>(d: D) -> Result<RelayMode, D::Error>
where
    D: Deserializer<'de>,
{
    let nodes = Vec::<RelayNode>::deserialize(d)?;
    Ok(RelayMode::Custom(
        RelayMap::from_nodes(nodes).map_err(serde::de::Error::custom)?,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct NodeConfig {
    data_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_relay_mode")]
    relay: RelayMode,
}

impl NodeConfig {
    pub async fn configure(&self) -> anyhow::Result<ProtocolBuilder<Store>> {
        let transport = TransportConfig::default();
        Node::persistent(&self.data_dir)
            .await?
            .enable_docs()
            .relay_mode(self.relay.clone())
            .transport_config(transport)
            .build()
            .await
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: "data".into(),
            relay: default_relay_mode(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TunConfig {
    name: String,
    pub addr: Ipv4Net,
    mtu: Option<u16>,
    #[cfg(target_os = "windows")]
    guid: Option<uuid::Uuid>,
}

impl TunConfig {
    pub fn configure(&self) -> tun2::Configuration {
        let mut config = tun2::configure();
        config
            .tun_name(&self.name)
            .address(self.addr.addr())
            .netmask(self.addr.netmask())
            .mtu(self.mtu.unwrap_or(1500))
            .up()
            .platform_config(|config| {
                #[cfg(target_os = "windows")]
                config.device_guid(self.guid.unwrap_or_else(uuid::Uuid::new_v4).as_u128());
                #[cfg(target_os = "linux")]
                config.ensure_root_privileges(true);
            });
        #[cfg(target_os = "windows")]
        config.metric(500);
        config
    }
}

#[serde_as]
#[derive(Debug, Deserialize)]
pub struct NetConfig {
    #[serde_as(as = "DisplayFromStr")]
    pub topic: TopicId,
    pub bootstrap: BTreeSet<NodeId>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "proto", rename_all = "lowercase")]
enum ProtoRule {
    Icmp,
    Tcp {
        src_port: Option<u16>,
        dest_port: Option<u16>,
    },
    Udp {
        src_port: Option<u16>,
        dest_port: Option<u16>,
    },
}

impl ProtoRule {
    fn allow(&self, pkt: &SlicedPacket) -> bool {
        match (self, &pkt.transport) {
            (Self::Icmp, Some(TransportSlice::Icmpv4(_))) => true,
            (
                Self::Tcp {
                    src_port,
                    dest_port,
                },
                Some(TransportSlice::Tcp(tcp)),
            ) => {
                src_port.map_or(true, |port| tcp.source_port() == port)
                    && dest_port.map_or(true, |port| tcp.destination_port() == port)
            }
            (
                Self::Udp {
                    src_port,
                    dest_port,
                },
                Some(TransportSlice::Udp(udp)),
            ) => {
                src_port.map_or(true, |port| udp.source_port() == port)
                    && dest_port.map_or(true, |port| udp.destination_port() == port)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct OutgoingRule {
    dest: Option<Ipv4Net>,
    #[serde(flatten)]
    proto: Option<ProtoRule>,
}

impl OutgoingRule {
    pub fn allow(&self, pkt: &SlicedPacket) -> bool {
        let allow_dest = match (&self.dest, &pkt.net) {
            (Some(dest), Some(NetSlice::Ipv4(ipv4))) => {
                dest.contains(&ipv4.header().destination_addr())
            }
            (None, _) => true,
            _ => false,
        };
        let allow_proto = self.proto.as_ref().map_or(true, |proto| proto.allow(pkt));
        allow_dest && allow_proto
    }
}

#[derive(Debug, Deserialize)]
pub struct IncomingRule {
    src: Option<Ipv4Net>,
    #[serde(flatten)]
    proto: Option<ProtoRule>,
}

impl IncomingRule {
    pub fn allow(&self, pkt: &SlicedPacket) -> bool {
        let allow_src = match (&self.src, &pkt.net) {
            (Some(src), Some(NetSlice::Ipv4(ipv4)))
                if src.contains(&ipv4.header().source_addr()) =>
            {
                true
            }
            (None, _) => true,
            _ => false,
        };
        let allow_proto = self.proto.as_ref().map_or(true, |proto| proto.allow(pkt));
        allow_src && allow_proto
    }
}
