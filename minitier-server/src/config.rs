use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use etherparse::{SlicedPacket, TransportSlice};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr, DurationSeconds};

#[serde_as]
#[derive(Deserialize)]
struct TransportConfig {
    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    max_idle_timeout: Option<Duration>,
    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    keep_alive_interval: Option<Duration>,
}

#[serde_as]
#[derive(Deserialize)]
pub struct ServerConfig {
    #[serde_as(as = "DisplayFromStr")]
    bind: SocketAddr,
    cert: PathBuf,
    key: PathBuf,
    transport: TransportConfig,
}

impl ServerConfig {
    fn configure(&self) -> anyhow::Result<quinn::ServerConfig> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            fs::read(&self.key).context("Failed to read private key")?,
        ));
        let cert_chain =
            CertificateDer::from(fs::read(&self.cert).context("Failed to read certificate chain")?);
        let mut server_config = quinn::ServerConfig::with_single_cert(vec![cert_chain], key)?;
        let transport = Arc::get_mut(&mut server_config.transport).unwrap();
        if let Some(timeout) = self.transport.max_idle_timeout {
            transport.max_idle_timeout(Some(timeout.try_into()?));
        }
        if let Some(interval) = self.transport.keep_alive_interval {
            transport.keep_alive_interval(Some(interval));
        }
        Ok(server_config)
    }

    pub fn bind(&self) -> anyhow::Result<quinn::Endpoint> {
        Ok(quinn::Endpoint::server(self.configure()?, self.bind)?)
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExcludeConfig {
    Tcp {
        src_port: Option<u16>,
        dst_port: Option<u16>,
    },
    Udp {
        src_port: Option<u16>,
        dst_port: Option<u16>,
    },
}

impl ExcludeConfig {
    pub fn check(&self, pkt: &SlicedPacket) -> bool {
        match self {
            Self::Tcp { src_port, dst_port } => {
                if let Some(TransportSlice::Tcp(tcp)) = &pkt.transport {
                    if src_port.map_or(true, |port| port == tcp.source_port())
                        && dst_port.map_or(true, |port| port == tcp.destination_port())
                    {
                        return true;
                    }
                }
            }
            Self::Udp { src_port, dst_port } => {
                if let Some(TransportSlice::Udp(udp)) = &pkt.transport {
                    if src_port.map_or(true, |port| port == udp.source_port())
                        && dst_port.map_or(true, |port| port == udp.destination_port())
                    {
                        return true;
                    }
                }
            }
        };
        false
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub exclude: Vec<ExcludeConfig>,
}
