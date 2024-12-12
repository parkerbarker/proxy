// tests/proxy_tests.rs
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

// Mock proxy configuration for testing
struct ProxyTestConfig {
    listen_port: u16,
    target_host: String,
    target_port: u16,
}

impl ProxyTestConfig {
    fn new(listen_port: u16, target_host: String, target_port: u16) -> Self {
        ProxyTestConfig {
            listen_port,
            target_host,
            target_port,
        }
    }

    // Simulated proxy connection test
    fn test_connection(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Bind a temporary listener to simulate server
        let server_listener = TcpListener::bind(format!("127.0.0.1:{}", self.target_port))?;

        // Spawn server thread
        let server_thread = thread::spawn(move || {
            for stream in server_listener.incoming() {
                match stream {
                    Ok(mut socket) => {
                        let mut buffer = [0; 1024];
                        socket.read(&mut buffer).unwrap();
                        socket
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
                            .unwrap();
                    }
                    Err(e) => eprintln!("Server error: {}", e),
                }
            }
        });

        // Client connection test
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", self.listen_port))?;
        client.write_all(b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")?;

        // Read response
        let mut buffer = [0; 1024];
        client.read(&mut buffer)?;

        // Validate response
        assert!(String::from_utf8_lossy(&buffer).contains("200 OK"));
        assert!(String::from_utf8_lossy(&buffer).contains("Hello"));

        Ok(())
    }

    // Performance benchmark test
    fn test_throughput(&self) -> Result<(), Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        const ITERATIONS: u32 = 100;

        for _ in 0..ITERATIONS {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", self.listen_port))?;
            client.write_all(b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")?;

            let mut buffer = [0; 1024];
            client.read(&mut buffer)?;
        }

        let duration = start.elapsed();
        println!(
            "Throughput Test: {} requests in {:.2?}",
            ITERATIONS, duration
        );

        // Basic performance assertion (adjust threshold as needed)
        assert!(duration < Duration::from_secs(5));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_connection() {
        let test_config = ProxyTestConfig::new(
            8081, // Proxy listen port
            "localhost".to_string(),
            8082, // Target server port
        );

        // Run connection test
        test_config
            .test_connection()
            .expect("Connection test failed");
    }

    #[test]
    fn test_proxy_throughput() {
        let test_config = ProxyTestConfig::new(
            8083, // Proxy listen port
            "localhost".to_string(),
            8084, // Target server port
        );

        // Run throughput test
        test_config
            .test_throughput()
            .expect("Throughput test failed");
    }
}
