use quinn::{Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
use serde_json::Value;
use rmp_serde::{from_read, to_vec};
use tokio::io::AsyncWriteExt;
use std::sync::Arc;
use std::net::SocketAddr;
use rcgen::generate_simple_self_signed;
use tokio::sync::{Semaphore, mpsc};
use thiserror::Error;
use tracing::{error, info, warn};
use std::fs::File;
use std::io::Write;
use clap::Parser;
use bytes::{ BytesMut, BufMut};
use quinn::ReadExactError;

#[derive(Error, Debug)]
enum ServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("Quinn write error: {0}")]
    QuinnWrite(#[from] quinn::WriteError),
    #[error("Quinn read error: {0}")]
    QuinnRead(#[from] quinn::ReadError),
    #[error("MessagePack error: {0}")]
    MessagePack(#[from] rmp_serde::decode::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Certificate generation error: {0}")]
    CertGen(#[from] rcgen::RcgenError),
    #[error("Encode error: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("Failed to send message to Logstash writer")]
    LogstashSend,
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Read exact error: {0}")]
    ReadExact(#[from] ReadExactError),
}


struct LogstashWriter {
    sender: mpsc::Sender<String>,
}

impl LogstashWriter {
    fn new(sender: mpsc::Sender<String>) -> Self {
        Self { sender }
    }

    async fn write_message(&self, message: String) -> Result<(), ServerError> {
        self.sender.send(message).await.map_err(|_| ServerError::LogstashSend)
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "127.0.0.1:4433")]
    server_addr: String,
    #[clap(short, long, default_value = "127.0.0.1:5000")]
    logstash_addr: String,
    #[clap(short, long, default_value = "1000")]
    max_connections: usize,
    #[clap(short, long, default_value = "server_cert.der")]
    cert_path: String,
    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let (cert, key) = generate_certificate(&args.cert_path)?;
    let server_config = create_server_config(cert, key)?;

    let addr: SocketAddr = args.server_addr.parse().expect("Valid address");
    let endpoint = Endpoint::server(server_config, addr)?;

    info!("Listening on {}", addr);

    let (sender, receiver) = mpsc::channel::<String>(100000);
    let logstash_writer = Arc::new(LogstashWriter::new(sender));

    spawn_logstash_writer_task(receiver, &args.logstash_addr);

    let sem = Arc::new(Semaphore::new(args.max_connections));

    run_server(endpoint, sem, logstash_writer, args.debug).await?;

    Ok(())
}

fn generate_certificate(cert_path: &str) -> Result<(Certificate, PrivateKey), ServerError> {
    let subject_alt_names = vec!["localhost".to_string()];
    let cert = generate_simple_self_signed(subject_alt_names)?;
    let cert_der = cert.serialize_der()?;
    let priv_key_der = cert.serialize_private_key_der();

    let mut cert_file = File::create(cert_path)?;
    cert_file.write_all(&cert_der)?;
    info!("Certificate written to {}", cert_path);

    Ok((Certificate(cert_der), PrivateKey(priv_key_der)))
}

fn create_server_config(cert: Certificate, key: PrivateKey) -> Result<ServerConfig, ServerError> {
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)?;
    let transport_config = Arc::new(quinn::TransportConfig::default());
    server_config.transport = transport_config;
    Ok(server_config)
}

fn spawn_logstash_writer_task(receiver: mpsc::Receiver<String>, addr: &str) {
    let addr = addr.to_string();
    tokio::spawn(async move {
        logstash_writer_task(receiver, &addr).await;
    });
}

async fn logstash_writer_task(mut receiver: mpsc::Receiver<String>, addr: &str) {
    let mut stream = match tokio::net::TcpStream::connect(addr).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to Logstash: {}", e);
            return;
        }
    };

    let mut buffer = Vec::with_capacity(1024 * 64); // 64KB buffer

    while let Some(message) = receiver.recv().await {
        buffer.extend_from_slice(message.as_bytes());
        buffer.push(b'\n');

        if buffer.len() >= 32 * 1024 { // 32KB threshold
            if let Err(e) = stream.write_all(&buffer).await {
                error!("Failed to write to Logstash: {}", e);
                return;
            }
            buffer.clear();
        }
    }

    // Flush remaining messages
    if !buffer.is_empty() {
        if let Err(e) = stream.write_all(&buffer).await {
            error!("Failed to write final messages to Logstash: {}", e);
        }
    }
}

async fn run_server(
    endpoint: Endpoint,
    sem: Arc<Semaphore>,
    logstash_writer: Arc<LogstashWriter>,
    debug: bool,
) -> Result<(), ServerError> {
    while let Some(conn) = endpoint.accept().await {
        let sem_clone = Arc::clone(&sem);
        let writer_clone = Arc::clone(&logstash_writer);
        tokio::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            if let Err(e) = handle_connection(conn, writer_clone, debug).await {
                error!("Connection error: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_connection(conn: quinn::Connecting, logstash_writer: Arc<LogstashWriter>, debug: bool) -> Result<(), ServerError> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();

    while let Ok((send, recv)) = connection.accept_bi().await {
        let writer_clone = Arc::clone(&logstash_writer);
        tokio::spawn(async move {
            if let Err(e) = process_request(send, recv, &writer_clone, debug).await {
                warn!("Error processing request from {}: {}", remote_addr, e);
            }
        });
    }
    Ok(())
}

async fn process_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    writer: &LogstashWriter,
    debug: bool,
) -> Result<(), ServerError> {
    let buf = read_length_prefixed_message(&mut recv).await?;
    let json_array: Vec<Value> = from_read(&buf[..])?;
    
    let mut responses = Vec::new();
    for json_value in json_array {
        if debug {
            println!("Received JSON: {}", json_value);
        }
        
        writer.write_message(json_value.to_string()).await?;
        responses.push(json_value);
    }

    let response = to_vec(&responses)?;
    send_length_prefixed_message(&mut send, &response).await?;

    Ok(())
}

async fn read_length_prefixed_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, ServerError> {
    let mut length_bytes = [0u8; 4];
    recv.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;

    if length > 10_000_000 { // 10 MB limit, adjust as needed
        return Err(ServerError::InvalidMessageLength);
    }

    let mut buf = vec![0u8; length];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn send_length_prefixed_message(send: &mut quinn::SendStream, data: &[u8]) -> Result<(), ServerError> {
    let length = data.len() as u32;
    let length_bytes = length.to_be_bytes();
    
    let mut message = BytesMut::with_capacity(4 + data.len());
    message.put_slice(&length_bytes);
    message.put_slice(data);

    send.write_all(&message).await?;
    send.finish().await?;
    Ok(())
}