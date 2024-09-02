# QUIC Logstash Server

This project implements a high-performance QUIC server that receives JSON messages, processes them, and forwards them to a Logstash instance. It's designed for efficient, secure, and reliable data ingestion in logging and metrics collection systems.

## Features

- QUIC protocol for fast, secure communication
- Multi-threaded request handling for high concurrency
- Self-signed certificate generation for easy setup
- Configurable connection limits and server address
- Efficient buffering and batching of messages to Logstash

## Dependencies

This server relies on several Rust crates, each serving a specific purpose:

- `quinn`: Implements the QUIC protocol for high-performance, secure networking
- `rustls`: Provides TLS functionality for secure connections
- `rmp_serde`: Handles MessagePack serialization and deserialization
- `tokio`: Powers the asynchronous runtime and I/O operations
- `rcgen`: Generates self-signed certificates for TLS
- `clap`: Parses command-line arguments
- `tracing`: Handles logging and instrumentation
- `serde_json`: Processes JSON data
- `crossbeam-channel`: Implements efficient multi-producer, multi-consumer channels
- `parking_lot`: Provides more efficient mutex implementations
- `bytes`: Helps with byte buffer management

## Main Code Flow

1. **Server Initialization**:
   - Parse command-line arguments
   - Generate a self-signed certificate
   - Create the QUIC server configuration
   - Set up the Logstash writer

2. **Main Server Loop** (`run_server` function):
   - Accept incoming QUIC connections
   - Spawn worker tasks to handle requests
   - Use a semaphore to limit the number of concurrent connections

3. **Connection Handling** (`handle_connection` function):
   - Accept bi-directional streams from each connection
   - Send streams to worker tasks for processing

4. **Request Processing** (`process_request` function):
   - Read length-prefixed JSON messages from the client
   - Parse and process JSON data
   - Forward messages to Logstash
   - Send acknowledgment back to the client

5. **Logstash Writing** (`logstash_writer_task` function):
   - Buffer incoming messages
   - Periodically flush messages to Logstash
   - Implement efficient write batching

## Key Functions

- `main`: Entry point, sets up the server and starts the main loop
- `generate_certificate`: Creates a self-signed certificate for TLS
- `create_server_config`: Configures the QUIC server
- `run_server`: Main server loop for accepting connections
- `worker_task`: Processes incoming requests in separate threads
- `process_request`: Handles individual client requests
- `logstash_writer_task`: Manages writing messages to Logstash

## Usage

```sh
cargo run -- [OPTIONS]

Options:
  -s, --server-addr <SERVER_ADDR>        [default: 127.0.0.1:4433]
  -l, --logstash-addr <LOGSTASH_ADDR>    [default: 127.0.0.1:5000]
  -m, --max-connections <MAX_CONNECTIONS> [default: 10000]
  -c, --cert-path <CERT_PATH>            [default: server_cert.der]
  -d, --debug
  -h, --help                             Print help
  -V, --version                          Print version
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

[MIT License](LICENSE)
