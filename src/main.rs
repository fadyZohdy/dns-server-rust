use bytes::Buf;
use std::net::UdpSocket;
use types::{Answer, Header, Label, Message};

mod parser;
mod types;

fn handle_connection(buf: [u8; 512]) -> anyhow::Result<Message> {
    let message = parser::parse_bytes_message(&mut buf.reader())?;
    let questions = message.questions;

    let answer = Answer {
        name: vec![Label("codecrafters".to_string()), Label("io".to_string())],
        record_type: types::RecordType::A,
        record_class: types::RecordClass::IN,
        ttl: 60,
        rdata: vec![8, 8, 8, 8],
    };
    let mut response_header = Header::new_reply(message.header.id);
    response_header.qdcount = questions.len() as u16;
    response_header.ancount = 1;
    Ok(Message {
        header: response_header,
        questions,
        answers: vec![answer],
        ..Default::default()
    })
}

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => match handle_connection(buf) {
                Ok(message) => {
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
            },
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
