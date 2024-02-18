use bytes::Buf;
use std::net::UdpSocket;
use types::{Header, Message};

mod parser;
mod types;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => {
                // println!("Received {} bytes from {}", size, source);
                match parser::parse_bytes_message(&mut buf.reader()) {
                    Ok(message) => {
                        let questions = message.questions;
                        let mut response_header = Header::new_reply(message.header.id);
                        response_header.qdcount = questions.len() as u16;
                        let message = Message {
                            header: response_header,
                            questions,
                            ..Default::default()
                        };
                        let response: Vec<u8> = message.try_into().unwrap();
                        udp_socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        udp_socket
                            .send_to(&[], source)
                            .expect("Failed to send response");
                    }
                };
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
