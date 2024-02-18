use std::io::Read;

use bytes::buf::Reader;

use crate::types::{Header, Label, Message, Question, RecordType};

fn read_byte(buff: &mut Reader<&[u8]>) -> anyhow::Result<u8> {
    let mut buf: [u8; 1] = [0; 1];

    buff.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn parse_header(buff: &mut Reader<&[u8]>) -> anyhow::Result<Header> {
    let mut header_buff: [u8; 12] = [0; 12];
    buff.read_exact(&mut header_buff)?;
    Header::try_from(header_buff)
}

fn parse_labels(buff: &mut Reader<&[u8]>) -> anyhow::Result<Vec<Label>> {
    let mut labels: Vec<Label> = vec![];
    while let Ok(b) = read_byte(buff) {
        if b == 0 {
            break;
        }
        let mut buf = vec![0; b as usize];
        buff.read_exact(&mut buf)?;
        let s = String::from_utf8(buf.to_vec())?;
        labels.push(Label(s));
    }
    Ok(labels)
}

fn parse_question(buff: &mut Reader<&[u8]>) -> anyhow::Result<Question> {
    let labels = parse_labels(buff)?;

    let mut buf: [u8; 2] = [0; 2];
    buff.read_exact(&mut buf)?;
    let record_type = RecordType::try_from(u16::from_be_bytes(buf.try_into().unwrap()))?;

    let q = Question {
        name: labels,
        record_type,
        ..Default::default()
    };
    Ok(q)
}

pub fn parse_bytes_message(buff: &mut Reader<&[u8]>) -> anyhow::Result<Message> {
    let header = parse_header(buff)?;

    let questions: Result<Vec<Question>, _> =
        (0..header.qdcount).map(|_| parse_question(buff)).collect();
    let questions = questions?;

    Ok(Message {
        header,
        questions,
        ..Default::default()
    })
}
