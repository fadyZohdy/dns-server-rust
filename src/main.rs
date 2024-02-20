use std::net::UdpSocket;
use types::{Answer, Header, Message, Question};

mod parser;
mod types;

fn forward_question(id: u16, question: &Question, socket: &UdpSocket) -> anyhow::Result<Answer> {
    let query_message = Message {
        header: Header {
            id,
            qdcount: 1,
            ..Default::default()
        },
        questions: vec![question.clone()],
        ..Default::default()
    };
    let message_bytes: Vec<u8> = query_message.try_into().unwrap();
    socket.send(message_bytes.as_slice())?;

    let mut buf = [0; 512];
    socket.recv(&mut buf)?;
    let mut dns_parser = parser::DnsParser {
        packet: buf.to_vec(),
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
        packet: buf.to_vec(),
        pos: 0,
    };
    let message = dns_parser.parse()?;
    let questions = message.questions;

    let mut answers: Vec<Answer> = vec![];

    if let Some(addr) = forwarding_addr {
        let forward_socket = UdpSocket::bind("127.0.0.1:8888").expect("Failed to bind to address");
        forward_socket.connect(addr.clone()).expect(&format!(
            "couldn't connect to forwarding server on {}",
            addr.clone()
        ));

        for question in questions.iter() {
            let answer = forward_question(message.header.id, question, &forward_socket)?;
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
