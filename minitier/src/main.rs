use std::fs;

use anyhow::Context;
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use quinn::ConnectionError;
use tokio::select;
use tracing::{error, info};

mod config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = enable_ansi_support::enable_ansi_support();
    tracing_subscriber::fmt::init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let config = toml::from_str::<config::Config>(
        &fs::read_to_string("minitier.toml").context("Failed to read configuration file")?,
    )
    .context("Failed to parse configuration file")?;

    let conn = config.server.connect().await?;
    info!("Connected to server");
    let mut stream = conn.open_uni().await?;
    stream.write_all(&config.tun.net()).await?;
    stream.finish()?;
    stream.stopped().await?;
    drop(stream);
    info!("Sent network configuration");

    let dev =
        tun2::create_as_async(&config.tun.configure()).context("Failed to create TUN device")?;

    let mut frames = dev.into_framed();
    loop {
        select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, shutting down");
                conn.close(0u8.into(), b"Shutting down");
                break;
            }
            err = conn.closed() => {
                if let ConnectionError::ApplicationClosed(_) = err {} else {
                    error!("Connection closed unexpectedly: {:?}", err);
                }
                break
            }
            Some(res) = frames.next() => {
                let data = res.context("Failed to read packet")?;
                let conn = conn.clone();
                tokio::spawn(async move {
                    let mut stream = conn.open_uni().await?;
                    stream.write_all(&data).await?;
                    stream.finish()?;
                    stream.stopped().await?;
                    anyhow::Ok(())
                });
            }
            res = conn
                .accept_uni()
                .map_err(anyhow::Error::from)
                .and_then(|mut stream| async move {
                    let data = stream.read_to_end(u16::MAX as usize).await?;
                    Ok(data)
                }) => {
                let data = res.context("Failed to read from QUIC stream")?;
                frames.send(data).await?;
            }
            else => anyhow::bail!("TUN device closed unexpectedly")
        }
    }

    Ok(())
}
