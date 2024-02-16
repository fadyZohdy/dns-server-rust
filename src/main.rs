// Uncomment this block to pass the first stage
use std::{default, net::UdpSocket};

// All communications in the DNS protocol are carried in a single format called a "message".
// Each message consists of 5 sections: header, question, answer, authority, and an additional space.

/**
    Packet Identifier (ID) 	            16 bits 	A random ID assigned to query packets. Response packets must reply with the same ID. Expected value: 1234.
    Query/Response Indicator (QR)       1 bit 	1 for a reply packet, 0 for a question packet. Expected value: 1.
    Operation Code (OPCODE)             4 bits 	Specifies the kind of query in a message. Expected value: 0.
    Authoritative Answer (AA)           1 bit 	1 if the responding server "owns" the domain queried, i.e., it's authoritative. Expected value: 0.
    Truncation (TC)                     1 bit 	1 if the message is larger than 512 bytes. Always 0 in UDP responses. Expected value: 0.
    Recursion Desired (RD) 	            1 bit 	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise. Expected value: 0.
    Recursion Available (RA)            1 bit 	Server sets this to 1 to indicate that recursion is available. Expected value: 0.
    Reserved (Z)                        3 bits 	Used by DNSSEC queries. At inception, it was reserved for future use. Expected value: 0.
    Response Code (RCODE)               4 bits 	Response code indicating the status of the response. Expected value: 0 (no error).
    Question Count (QDCOUNT)            16 bits 	Number of questions in the Question section. Expected value: 0.
    Answer Record Count (ANCOUNT)       16 bits 	Number of records in the Answer section. Expected value: 0.
    Authority Record Count (NSCOUNT) 	16 bits 	Number of records in the Authority section. Expected value: 0.
    Additional Record Count (ARCOUNT) 	16 bits 	Number of records in the Additional section. Expected value: 0.
*/

#[derive(Default)]
struct Header {
    id: [u8; 2],
    flags: [u8; 2],
    qdcount: [u8; 2],
    ancount: [u8; 2],
    nscount: [u8; 2],
    arcount: [u8; 2],
}

impl Header {
    fn new_query() -> Self {
        Header::default()
    }
    fn new_reply(id: [u8; 2]) -> Self {
        let mut h = Header::default();
        h.flags[0] |= 0b1000_0000;
        h
    }
    fn set_id(&mut self, id: [u8; 2]) {
        self.id = id;
    }
}

impl TryFrom<[u8; 12]> for Header {
    type Error = anyhow::Error;

    fn try_from(bytes: [u8; 12]) -> anyhow::Result<Header, Self::Error> {
        let header = Header {
            id: bytes[..2].try_into()?,
            flags: bytes[2..4].try_into()?,
            qdcount: bytes[4..6].try_into()?,
            ancount: bytes[6..8].try_into()?,
            nscount: bytes[8..10].try_into()?,
            arcount: bytes[10..12].try_into()?
        };

        Ok(header)
    }
}

impl TryInto<[u8; 12]> for Header {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[u8; 12], Self::Error> {
        let mut r = Vec::with_capacity(12);
        r.extend_from_slice(&self.id);
        r.extend_from_slice(&self.flags);
        r.extend_from_slice(&self.qdcount);
        r.extend_from_slice(&self.ancount);
        r.extend_from_slice(&self.nscount);
        r.extend_from_slice(&self.arcount);
        Ok(r.as_slice().try_into().unwrap())
    }
}

#[derive(Default)]
struct Question {}
#[derive(Default)]
struct Answer {}
#[derive(Default)]
struct Authority {}
#[derive(Default)]
struct Additional {}

#[derive(Default)]
struct Message {
    header: Header,
    question: Question,
    answer: Answer,
    authority: Authority,
    additional: Additional
}

impl TryInto<Vec<u8>> for Message {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Vec<u8>, Self::Error> {
        let mut r = Vec::with_capacity(512);
        let header_bytes: [u8; 12] = self.header.try_into()?;
        r.extend_from_slice(&header_bytes);
        Ok(r)
    }
}



fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                // println!("Received {} bytes from {}", size, source);
                let header_bytes: [u8; 12] = buf[..12].try_into().unwrap();
                match Header::try_from(header_bytes) {
                    Ok(request_header) => {
                        let mut response_header = Header::new_reply(request_header.id);
                        response_header.set_id(request_header.id);
                        let message = Message {
                            header: response_header,
                            ..Default::default()
                        };
                        let response: Vec<u8> = message.try_into().unwrap(); 
                    udp_socket
                        .send_to(&response, source)
                        .expect("Failed to send response");
                    },
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
