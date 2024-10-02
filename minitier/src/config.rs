use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::Context;
use ipnet::Ipv4Net;
use quinn::rustls;
use serde::Deserialize;
use tokio::net::lookup_host;
use url::Url;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ServerConfig {
    url: Url,
    host: Option<String>,
    #[serde(default)]
    insecure: bool,
    cert: Option<PathBuf>,
    bind: Option<SocketAddr>,
}

impl ServerConfig {
    async fn resolve(&self) -> anyhow::Result<(SocketAddr, &str)> {
        let host = strip_ipv6_brackets(
            self.url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Wrong server url: host missing"))?,
        );
        let port = self.url.port().unwrap_or(50500);
        let remote = lookup_host((host, port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Couldn't resolve to an address"))?;
        Ok((remote, self.host.as_deref().unwrap_or(host)))
    }

    fn configure(&self) -> anyhow::Result<quinn::ClientConfig> {
        let config = if self.insecure {
            let mut config = rustls::ClientConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(insecure::SkipServerVerification::default()))
            .with_no_client_auth();
            config.enable_early_data = true;

            quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(
                config,
            )?))
        } else if let Some(cert_path) = &self.cert {
            let cert = fs::read(cert_path).context("Failed to read certificate")?;
            let mut roots = rustls::RootCertStore::empty();
            roots.add(rustls::pki_types::CertificateDer::from(cert))?;
            quinn::ClientConfig::with_root_certificates(Arc::new(roots))?
        } else {
            quinn::ClientConfig::with_platform_verifier()
        };
        Ok(config)
    }

    pub async fn connect(&self) -> anyhow::Result<quinn::Connection> {
        let (remote, host) = self.resolve().await?;
        let mut endpoint = quinn::Endpoint::client(
            self.bind
                .unwrap_or(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
        )
        .context("Failed to create QUIC endpoint")?;
        endpoint.set_default_client_config(self.configure()?);
        let connection = endpoint
            .connect(remote, host)?
            .await
            .context("Failed to connect to server")?;
        Ok(connection)
    }
}

#[derive(Deserialize)]
pub struct TunConfig {
    name: String,
    addr: Ipv4Net,
    dest: Ipv4Addr,
    guid: Option<Uuid>,
}

impl TunConfig {
    pub fn configure(&self) -> tun2::Configuration {
        let mut config = tun2::configure();
        config
            .address(self.addr.addr())
            .netmask(self.addr.netmask())
            .destination(self.dest)
            .tun_name(&self.name)
            .mtu(tun2::DEFAULT_MTU)
            .metric(500)
            .up()
            .platform_config(|config| {
                config.device_guid(self.guid.unwrap_or_else(Uuid::new_v4).as_u128());
            });
        config
    }

    pub fn net(&self) -> [u8; 5] {
        let [a, b, c, d] = self.addr.addr().octets();
        [a, b, c, d, self.addr.prefix_len()]
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tun: TunConfig,
}

fn strip_ipv6_brackets(host: &str) -> &str {
    // An ipv6 url looks like eg https://[::1]:4433/Cargo.toml, wherein the host [::1] is the
    // ipv6 address ::1 wrapped in brackets, per RFC 2732. This strips those.
    if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    }
}

mod insecure {
    use quinn::rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, Error, SignatureScheme,
    };

    #[derive(Debug)]
    pub struct SkipServerVerification(WebPkiSupportedAlgorithms);

    impl Default for SkipServerVerification {
        fn default() -> Self {
            SkipServerVerification(ring::default_provider().signature_verification_algorithms)
        }
    }

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }
}
