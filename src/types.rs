use bytes::{BufMut, BytesMut};

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

#[derive(Debug, Default)]
pub struct Header {
    pub id: u16,
    pub flags: [u8; 2],
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn new_reply(id: u16) -> Self {
        let mut h = Header::default();
        h.id = id;
        h.flags[0] |= 0b1000_0000;
        h
    }
}

impl TryFrom<[u8; 12]> for Header {
    type Error = anyhow::Error;

    fn try_from(bytes: [u8; 12]) -> anyhow::Result<Header, Self::Error> {
        let header = Header {
            id: u16::from_be_bytes(bytes[..2].try_into()?),
            flags: bytes[2..4].try_into()?,
            qdcount: u16::from_be_bytes(bytes[4..6].try_into()?),
            ancount: u16::from_be_bytes(bytes[6..8].try_into()?),
            nscount: u16::from_be_bytes(bytes[8..10].try_into()?),
            arcount: u16::from_be_bytes(bytes[10..12].try_into()?),
        };

        Ok(header)
    }
}

impl TryInto<[u8; 12]> for Header {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<[u8; 12], Self::Error> {
        let mut r = BytesMut::with_capacity(12);
        r.put_u16(self.id);
        r.extend_from_slice(&self.flags);
        r.put_u16(self.qdcount);
        r.put_u16(self.ancount);
        r.put_u16(self.nscount);
        r.put_u16(self.arcount);
        Ok(r[..].try_into().unwrap())
    }
}

#[derive(Debug, Default)]
pub enum RecordType {
    #[default]
    A,
    NS,
    CNAME,
    MX,
}

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> anyhow::Result<RecordType, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            5 => Ok(RecordType::CNAME),
            15 => Ok(RecordType::MX),
            _ => Err(anyhow::anyhow!("Unknown record type: {}", value)),
        }
    }
}

impl Into<u16> for RecordType {
    fn into(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::MX => 15,
        }
    }
}

#[derive(Debug, Default)]
pub struct Label(pub String);

impl Into<Vec<u8>> for Label {
    fn into(self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.0.len() as u8);
        buf.put(self.0.as_bytes());
        buf.into()
    }
}

#[derive(Debug, Default)]
pub enum RecordClass {
    #[default]
    IN,
}

impl Into<u16> for RecordClass {
    fn into(self) -> u16 {
        match self {
            RecordClass::IN => 1,
        }
    }
}

/**
   Each question has the following structure:
       Name: A domain name, represented as a sequence of "labels"
       Type: 2-byte int; the type of record (1 for an A record, 5 for a CNAME record etc.)
       Class: 2-byte int; usually set to 1
*/
#[derive(Debug, Default)]
pub struct Question {
    pub labels: Vec<Label>,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl Into<Vec<u8>> for Question {
    fn into(self) -> Vec<u8> {
        let mut buf = BytesMut::new();

        self.labels.into_iter().for_each(|l| {
            let label_bytes: Vec<u8> = l.into();
            buf.extend_from_slice(label_bytes.as_slice());
        });
        buf.put_u8(0);

        buf.put_u16(self.record_type.into());

        buf.put_u16(self.record_class.into());

        buf.into()
    }
}

#[derive(Default)]
pub struct Answer {}

#[derive(Default)]
pub struct Authority {}

#[derive(Default)]
pub struct Additional {}

#[derive(Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answer: Answer,
    pub authority: Authority,
    pub additional: Additional,
}

impl TryInto<Vec<u8>> for Message {
    type Error = anyhow::Error;

    fn try_into(self) -> anyhow::Result<Vec<u8>, Self::Error> {
        let mut r = BytesMut::with_capacity(512);
        let header_bytes: [u8; 12] = self.header.try_into()?;
        r.extend_from_slice(&header_bytes);
        self.questions.into_iter().for_each(|q| {
            let q_bytes: Vec<u8> = q.into();
            r.extend_from_slice(q_bytes.as_slice());
        });
        Ok(r.into())
    }
}
