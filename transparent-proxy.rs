# Rust Implementation (proxy.rs)
use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;

#[derive(Debug)]
struct ProxyConfig {
    listen_port: u16,
    target_host: String,
    target_port: u16,
}

impl ProxyConfig {
    fn new(listen_port: u16, target_host: String, target_port: u16) -> Self {
        ProxyConfig {
            listen_port,
            target_host,
            target_port,
        }
    }

    fn start(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.listen_port))?;
        println!("Proxy listening on port {}", self.listen_port);

        for stream in listener.incoming() {
            match stream {
                Ok(client_stream) => {
                    let config = self.clone();
                    thread::spawn(move || {
                        if let Err(e) = config.handle_connection(client_stream) {
                            eprintln!("Connection error: {}", e);
                        }
                    });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
        Ok(())
    }

    fn handle_connection(&self, mut client_stream: TcpStream) -> std::io::Result<()> {
        // Connect to target server
        let mut server_stream = TcpStream::connect(
            format!("{}:{}", self.target_host, self.target_port)
        )?;

        // Clone streams for bidirectional proxy
        let mut client_read = client_stream.try_clone()?;
        let mut server_read = server_stream.try_clone()?;
        let mut client_write = client_stream;
        let mut server_write = server_stream;

        // Spawn threads for bidirectional data transfer
        let client_to_server = thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match client_read.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Potential Ruby hook for request modification
                        if let Err(e) = server_write.write_all(&buffer[0..n]) {
                            eprintln!("Write to server failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Read from client failed: {}", e);
                        break;
                    }
                }
            }
        });

        let server_to_client = thread::spawn(move || {
            let mut buffer = [0; 4096];
            loop {
                match server_read.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Potential Ruby hook for response modification
                        if let Err(e) = client_write.write_all(&buffer[0..n]) {
                            eprintln!("Write to client failed: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Read from server failed: {}", e);
                        break;
                    }
                }
            }
        });

        client_to_server.join().unwrap();
        server_to_client.join().unwrap();

        Ok(())
    }
}

fn main() {
    let config = ProxyConfig::new(
        8080,           // Listen port
        "example.com".to_string(),  // Target host
        80              // Target port
    );

    if let Err(e) = config.start() {
        eprintln!("Proxy failed to start: {}", e);
    }
}
