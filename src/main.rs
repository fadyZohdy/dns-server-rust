use std::net::UdpSocket;
use types::{Answer, Header, Message, OpCode, RCode};

mod parser;
mod types;

fn forward_message(message: Message, socket: &UdpSocket) -> anyhow::Result<Answer> {
    let message_bytes: Vec<u8> = message.try_into().unwrap();
    socket.send(message_bytes.as_slice())?;

    let mut buf = [0; 512];
    socket.recv(&mut buf)?;
    let mut dns_parser = parser::DnsParser {
        packet: buf,
        pos: 0,
    };
    let answer_message = dns_parser.parse()?;

    if let Some(answer) = answer_message.answers.first() {
        Ok(answer.clone())
    } else {
        Err(anyhow::anyhow!("didn't get an answer from remote"))
    }
}

fn handle_connection(buf: [u8; 512], forwarding_addr: Option<String>) -> anyhow::Result<Message> {
    let mut dns_parser = parser::DnsParser {
        packet: buf,
        pos: 0,
    };
    let query_message = dns_parser.parse()?;
    let id = query_message.header.id;
    let opcode = query_message.header.get_opcode()?;
    let questions = query_message.clone().questions;

    let response_header = Header::new_reply(id);
    let mut response_message = Message {
        header: response_header,
        questions: questions.clone(),
        ..Default::default()
    };
    response_message.header.qdcount = questions.len() as u16;
    response_message.header.set_opcode(opcode);
    response_message
        .header
        .set_rd(query_message.header.get_rd());

    if opcode != OpCode::Query {
        response_message.header.set_rcode(RCode::NotImplemented);
        return Ok(response_message);
    }

    let mut answers: Vec<Answer> = vec![];

    if let Some(addr) = forwarding_addr {
        let forward_socket = UdpSocket::bind("127.0.0.1:8888").expect("Failed to bind to address");
        forward_socket.connect(addr.clone()).unwrap_or_else(|_| {
            panic!("couldn't connect to forwarding server on {}", addr.clone())
        });
        for i in 0..query_message.header.qdcount {
            let mut forwarding_message = query_message.clone();
            forwarding_message.questions = vec![questions[i as usize].clone()];
            let answer = forward_message(forwarding_message, &forward_socket)?;
            answers.push(answer);
        }
    } else {
        for question in questions.iter() {
            let a = Answer {
                name: question.name.clone(),
                record_type: question.record_type,
                record_class: question.record_class,
                ttl: 60,
                rdata: vec![8, 8, 8, 8],
            };
            answers.push(a);
        }
    }

    response_message.header.ancount = answers.len() as u16;
    response_message.answers = answers;
    response_message.header.set_rcode(RCode::NoError);

    Ok(response_message)
}

fn main() {
    let mut forwarding_addr: Option<String> = None;
    let args: Vec<_> = std::env::args().map(|a| a.to_string()).collect();
    for i in 0..args.len() {
        if args[i] == "--resolver" {
            forwarding_addr = Some(args[i + 1].clone());
            break;
        }
    }

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((_, source)) => match handle_connection(buf, forwarding_addr.clone()) {
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
