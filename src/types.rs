use bytes::{BufMut, BytesMut};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OpCode {
    Query,
    IQuery,
    Status,
    Reserved(u8),
}

impl From<OpCode> for u8 {
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::Reserved(n) => n,
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> anyhow::Result<OpCode, Self::Error> {
        match value {
            0 => Ok(OpCode::Query),
            1 => Ok(Self::IQuery),
            2 => Ok(OpCode::Status),
            3..=15 => Ok(Self::Reserved(value)),
            _ => Err(anyhow::anyhow!("unknown opcode: {value}")),
        }
    }
}

#[derive(Clone, Copy)]
pub enum RCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl From<RCode> for u8 {
    fn from(value: RCode) -> Self {
        match value {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
        }
    }
}

#[derive(Clone, Debug, Default)]
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
        let mut h = Header {
            id,
            ..Default::default()
        };
        h.flags[0] |= 0b1000_0000;
        h
    }

    pub fn get_opcode(&self) -> anyhow::Result<OpCode> {
        ((self.flags[0] & 0b0111_1000) >> 3).try_into()
    }

    pub fn set_opcode(&mut self, opcode: OpCode) {
        let value: u8 = opcode.into();
        let mask = (value << 3) & 0b0111_1000;
        self.flags[0] |= mask;
    }

    pub fn get_rd(&self) -> bool {
        let mask = 0b0000_0001;
        self.flags[0] & mask > 0
    }

    pub fn set_rd(&mut self, rd: bool) {
        if rd {
            let mask = 0b0000_0001;
            self.flags[0] |= mask;
        } else {
            let mask = 0b0000_0000;
            self.flags[0] |= mask;
        }
    }

    // 0 (no error) if OPCODE is 0 (standard query) else 4 (not implemented)
    pub fn set_rcode(&mut self, rcode: RCode) {
        let mask: u8 = rcode.into();
        self.flags[1] |= mask;
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

#[derive(Copy, Clone, Debug, Default)]
pub enum RecordType {
    #[default]
    A,
    NS,
    Cname,
    MX,
}

impl TryFrom<u16> for RecordType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> anyhow::Result<RecordType, Self::Error> {
        match value {
            1 => Ok(RecordType::A),
            2 => Ok(RecordType::NS),
            5 => Ok(RecordType::Cname),
            15 => Ok(RecordType::MX),
            _ => Err(anyhow::anyhow!("Unknown record type: {}", value)),
        }
    }
}

impl From<RecordType> for u16 {
    fn from(val: RecordType) -> Self {
        match val {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::Cname => 5,
            RecordType::MX => 15,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Label(pub String);

impl From<Label> for Vec<u8> {
    fn from(val: Label) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8(val.0.len() as u8);
        buf.put(val.0.as_bytes());
        buf.into()
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub enum RecordClass {
    #[default]
    IN,
}

impl From<RecordClass> for u16 {
    fn from(val: RecordClass) -> Self {
        match val {
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
#[derive(Clone, Debug, Default)]
pub struct Question {
    pub name: Vec<Label>,
    pub record_type: RecordType,
    pub record_class: RecordClass,
}

impl From<Question> for Vec<u8> {
    fn from(val: Question) -> Self {
        let mut buf = BytesMut::new();

        val.name.into_iter().for_each(|l| {
            let label_bytes: Vec<u8> = l.into();
            buf.extend_from_slice(label_bytes.as_slice());
        });
        buf.put_u8(0);

        buf.put_u16(val.record_type.into());

        buf.put_u16(val.record_class.into());

        buf.into()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Answer {
    pub name: Vec<Label>,
    pub record_type: RecordType,
    pub record_class: RecordClass,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl From<Answer> for Vec<u8> {
    fn from(val: Answer) -> Self {
        let mut buf = BytesMut::with_capacity(512);
        val.name.into_iter().for_each(|l| {
            let label_bytes: Vec<u8> = l.into();
            buf.extend_from_slice(label_bytes.as_slice());
        });
        buf.put_u8(0);

        buf.put_u16(val.record_type.into());

        buf.put_u16(val.record_class.into());

        buf.put_u32(val.ttl);

        // rdlength
        buf.put_u16(val.rdata.len() as u16);

        buf.extend_from_slice(&val.rdata[..]);

        buf.into()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Authority {}

#[derive(Clone, Debug, Default)]
pub struct Additional {}

#[derive(Clone, Debug, Default)]
pub struct Message {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
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

        self.answers.into_iter().for_each(|a| {
            let a_bytes: Vec<u8> = a.into();
            r.extend_from_slice(a_bytes.as_slice());
        });
        Ok(r.into())
    }
}
