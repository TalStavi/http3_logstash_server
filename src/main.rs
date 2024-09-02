//! QUIC Server for Logstash
//! 
//! This module implements a QUIC server that receives JSON messages,
//! processes them, and forwards them to a Logstash instance.
//! 
//! The server uses the quinn crate for QUIC protocol implementation and
//! supports multi-threading for efficient request handling.

use quinn::{Endpoint, ServerConfig};
use rustls::{Certificate, PrivateKey};
use rmp_serde::from_read;
use tokio::io::AsyncReadExt;
use std::sync::Arc;
use std::net::SocketAddr;
use rcgen::generate_simple_self_signed;
use tokio::sync::{mpsc, Semaphore};
use thiserror::Error;
use tracing::{error, info, warn};
use std::fs::File;
use std::io::Write;
use clap::Parser;
use bytes::BytesMut;
use quinn::ReadExactError;
use crossbeam_channel::{bounded, Sender, Receiver};
use num_cpus;
use serde_json::Value;
use tokio::task;
use parking_lot::Mutex;
use tokio::time::{sleep, Duration};

/// Maximum message size in bytes (10 MB)
const MAX_MESSAGE_SIZE: usize = 10_000_000;

/// Buffer size for logstash writer (64 KB)
const LOGSTASH_BUFFER_SIZE: usize = 64 * 1024;

/// Threshold for flushing logstash buffer (32 KB)
const LOGSTASH_FLUSH_THRESHOLD: usize = 32 * 1024;

/// Acknowledgment message sent back to clients
const ACK_MESSAGE: &[u8] = b"\x03ACK";

/// Error types for the server
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
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Certificate generation error: {0}")]
    CertGen(#[from] rcgen::RcgenError),
    #[error("Invalid message length")]
    InvalidMessageLength,
    #[error("Read exact error: {0}")]
    ReadExact(#[from] ReadExactError),
}

/// Struct for writing messages to Logstash
struct LogstashWriter {
    sender: Sender<String>,
}

impl LogstashWriter {
    /// Creates a new LogstashWriter
    fn new(sender: Sender<String>) -> Self {
        Self { sender }
    }

    /// Writes a message to the Logstash queue
    fn write_message(&self, message: String) -> Result<(), ServerError> {
        self.sender.send(message).map_err(|_| ServerError::Io(std::io::Error::new(std::io::ErrorKind::Other, "Failed to send message to Logstash writer")))
    }
}

/// Command line arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value = "127.0.0.1:4433")]
    server_addr: String,
    #[clap(short, long, default_value = "127.0.0.1:5000")]
    logstash_addr: String,
    #[clap(short, long, default_value = "10000")]
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

    let (sender, receiver) = bounded(100000);
    let logstash_writer = Arc::new(LogstashWriter::new(sender));

    spawn_logstash_writer_task(receiver, &args.logstash_addr);

    let sem = Arc::new(Semaphore::new(args.max_connections));

    run_server(endpoint, sem, logstash_writer, args.debug).await?;

    Ok(())
}

/// Generates a self-signed certificate
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

/// Creates the server configuration
fn create_server_config(cert: Certificate, key: PrivateKey) -> Result<ServerConfig, ServerError> {
    let mut server_config = ServerConfig::with_single_cert(vec![cert], key)?;
    let transport_config = Arc::new(quinn::TransportConfig::default());
    server_config.transport = transport_config;
    Ok(server_config)
}

/// Spawns the Logstash writer task
fn spawn_logstash_writer_task(receiver: Receiver<String>, addr: &str) {
    let addr = addr.to_string();
    std::thread::spawn(move || {
        if let Err(e) = logstash_writer_task(receiver, &addr) {
            error!("Logstash writer task failed: {:?}", e);
        }
    });
}

/// Task for writing messages to Logstash
fn logstash_writer_task(receiver: Receiver<String>, addr: &str) -> Result<(), std::io::Error> {
    use std::net::TcpStream;
    use std::io::BufWriter;

    let stream = TcpStream::connect(addr)?;
    let mut writer = BufWriter::new(stream);

    let mut buffer = String::with_capacity(LOGSTASH_BUFFER_SIZE);

    while let Ok(message) = receiver.recv() {
        buffer.push_str(&message);
        buffer.push('\n');

        if buffer.len() >= LOGSTASH_FLUSH_THRESHOLD {
            flush_buffer(&mut writer, &mut buffer)?;
        }
    }

    // Flush remaining messages
    if !buffer.is_empty() {
        flush_buffer(&mut writer, &mut buffer)?;
    }

    Ok(())
}

/// Flushes the buffer to the writer
fn flush_buffer(writer: &mut impl Write, buffer: &mut String) -> Result<(), std::io::Error> {
    writer.write_all(buffer.as_bytes())?;
    writer.flush()?;
    buffer.clear();
    Ok(())
}

/// Runs the main server loop
async fn run_server(
    endpoint: Endpoint,
    sem: Arc<Semaphore>,
    logstash_writer: Arc<LogstashWriter>,
    debug: bool,
) -> Result<(), ServerError> {
    let (request_tx, request_rx) = mpsc::channel::<(quinn::SendStream, quinn::RecvStream)>(10000);
    let request_rx = Arc::new(Mutex::new(request_rx));

    spawn_worker_tasks(Arc::clone(&request_rx), Arc::clone(&logstash_writer), debug);

    while let Some(conn) = endpoint.accept().await {
        let sem_clone = Arc::clone(&sem);
        let request_tx = request_tx.clone();
        task::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();
            if let Err(e) = handle_connection(conn, request_tx).await {
                error!("Connection error: {}", e);
            }
        });
    }
    Ok(())
}

/// Spawns worker tasks for processing requests
fn spawn_worker_tasks(
    request_rx: Arc<Mutex<mpsc::Receiver<(quinn::SendStream, quinn::RecvStream)>>>,
    logstash_writer: Arc<LogstashWriter>,
    debug: bool,
) {
    let num_workers = num_cpus::get();
    for _ in 0..num_workers {
        let request_rx = Arc::clone(&request_rx);
        let logstash_writer = Arc::clone(&logstash_writer);
        let debug = debug;
        
        task::spawn(async move {
            worker_task(request_rx, logstash_writer, debug).await;
        });
    }
}

/// Worker task for processing requests
async fn worker_task(
    request_rx: Arc<Mutex<mpsc::Receiver<(quinn::SendStream, quinn::RecvStream)>>>,
    logstash_writer: Arc<LogstashWriter>,
    debug: bool,
) {
    let mut buf = BytesMut::with_capacity(65536);
    loop {
        let msg = {
            // Only hold the lock for the duration of try_recv()
            request_rx.lock().try_recv()
        };

        match msg {
            Ok((send, mut recv)) => {
                if let Err(e) = process_request(&mut buf, send, &mut recv, &logstash_writer, debug).await {
                    warn!("Error processing request: {}", e);
                }
                buf.clear();
            }
            Err(mpsc::error::TryRecvError::Empty) => {
                // Sleep without holding the lock
                sleep(Duration::from_millis(1)).await;
            }
            Err(mpsc::error::TryRecvError::Disconnected) => break,
        }
    }
}

/// Handles incoming connections
async fn handle_connection(
    conn: quinn::Connecting,
    request_tx: mpsc::Sender<(quinn::SendStream, quinn::RecvStream)>,
) -> Result<(), ServerError> {
    let connection = conn.await?;
    while let Ok((send, recv)) = connection.accept_bi().await {
        if request_tx.send((send, recv)).await.is_err() {
            warn!("Failed to send request to worker");
        }
    }
    Ok(())
}

/// Processes a single request
async fn process_request(
    buf: &mut BytesMut,
    mut send: quinn::SendStream,
    recv: &mut quinn::RecvStream,
    writer: &LogstashWriter,
    debug: bool,
) -> Result<(), ServerError> {
    buf.clear();
    read_length_prefixed_message(recv, buf).await?;
    let json_array: Vec<Value> = from_read(&buf[..])?;
    
    for json_value in json_array {
        if debug {
            println!("Received JSON: {}", json_value);
        }
        
        writer.write_message(json_value.to_string())?;
    }

    send_acknowledgment(&mut send).await?;

    Ok(())
}

/// Reads a length-prefixed message from the stream
async fn read_length_prefixed_message(recv: &mut quinn::RecvStream, buf: &mut BytesMut) -> Result<(), ServerError> {
    let mut length_bytes = [0u8; 4];
    recv.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;

    if length > MAX_MESSAGE_SIZE {
        return Err(ServerError::InvalidMessageLength);
    }

    buf.reserve(length);
    while buf.len() < length {
        let bytes_read = recv.read_buf(buf).await?;
        if bytes_read == 0 {
            return Err(ServerError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Connection closed prematurely",
            )));
        }
    }
    Ok(())
}

/// Sends an acknowledgment message back to the client
async fn send_acknowledgment(send: &mut quinn::SendStream) -> Result<(), ServerError> {
    send.write_all(ACK_MESSAGE).await?;
    send.finish().await?;
    Ok(())
}