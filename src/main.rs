use std::net::UdpSocket;
use types::{Answer, Header, Message};

mod parser;
mod types;

fn handle_connection(buf: [u8; 512]) -> anyhow::Result<Message> {
    //let message = parser::parse_bytes_message(&mut buf.reader())?;
    let mut dns_parser = parser::DnsParser {
        packet: buf.to_vec(),
        pos: 0,
    };
    let message = dns_parser.parse()?;
    let questions = message.questions;

    let answers: Vec<_> = questions
        .iter()
        .map(|q| Answer {
            name: q.name.clone(),
            record_type: q.record_type,
            record_class: q.record_class,
            ttl: 60,
            rdata: vec![8, 8, 8, 8],
        })
        .collect();

    let mut response_header = Header::new_reply(message.header.id);
    response_header.qdcount = questions.len() as u16;
    response_header.ancount = answers.len() as u16;
    response_header.set_opcode(message.header.get_opcode());
    response_header.set_rd(message.header.get_rd());
    response_header.set_rcode(message.header.get_opcode());

    Ok(Message {
        header: response_header,
        questions,
        answers,
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
