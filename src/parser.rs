use crate::types::{Answer, Header, Label, Message, Question, RecordType};

pub struct DnsParser {
    pub packet: Vec<u8>,
    pub pos: usize,
}

impl DnsParser {
    fn parse_header(&mut self) -> anyhow::Result<Header> {
        let header_bytes: [u8; 12] = self.packet[0..12].try_into()?;
        self.pos = 12;
        Header::try_from(header_bytes)
    }

    fn parse_labels(&mut self) -> anyhow::Result<Vec<Label>> {
        let mut labels: Vec<Label> = vec![];
        while let Some(b) = self.packet.get(self.pos) {
            self.pos += 1;
            // null terminator
            if *b == 0 {
                break;
            }

            // jump instruction
            if (*b & 0b1100_0000) == 0b1100_0000 {
                // if the two Most Significant Bits of the length is set, we can instead expect the length byte to be followed by a second byte.
                // These two bytes taken together, and removing the two MSB's, indicate the jump position
                // get the jump position
                let jump_pos = u16::from_be_bytes([*b & 0b0011_1111, self.packet[self.pos]]);
                self.pos += 1;
                let current_pos = self.pos;
                self.pos = jump_pos as usize;
                labels.extend(self.parse_labels()?);
                self.pos = current_pos;
                return Ok(labels);
            }

            let length = *b as usize;
            // skip the length byte
            let s = String::from_utf8(self.packet[self.pos..self.pos + length].to_vec())?;
            labels.push(Label(s));
            self.pos += length;
        }
        Ok(labels)
    }

    fn parse_question(&mut self) -> anyhow::Result<Question> {
        let labels = self.parse_labels()?;

        let record_type = RecordType::try_from(u16::from_be_bytes(
            self.packet[self.pos..=self.pos + 1].try_into()?,
        ))?;
        // skip record type bytes
        self.pos += 2;

        // skip record class bytes
        self.pos += 2;

        let q = Question {
            name: labels,
            record_type,
            ..Default::default()
        };
        Ok(q)
    }

    fn parse_answer(&mut self) -> anyhow::Result<Answer> {
        let labels = self.parse_labels()?;

        let record_type = RecordType::try_from(u16::from_be_bytes(
            self.packet[self.pos..=self.pos + 1].try_into()?,
        ))?;
        // skip record type bytes
        self.pos += 2;

        // skip record class bytes
        self.pos += 2;

        let ttl = u32::from_be_bytes(self.packet[self.pos..self.pos + 4].try_into()?);
        self.pos += 4;

        let rdlength = u16::from_be_bytes(self.packet[self.pos..self.pos + 2].try_into()?);
        self.pos += 2;

        let rdata = self.packet[self.pos..self.pos + rdlength as usize].to_vec();
        self.pos += rdlength as usize;

        let q = Answer {
            name: labels,
            record_type,
            ttl,
            rdata,
            ..Default::default()
        };
        Ok(q)
    }

    pub fn parse(&mut self) -> anyhow::Result<Message> {
        let header = self.parse_header()?;

        let questions: Result<Vec<Question>, _> =
            (0..header.qdcount).map(|_| self.parse_question()).collect();
        let questions = questions?;

        let answers: Result<Vec<Answer>, _> =
            (0..header.ancount).map(|_| self.parse_answer()).collect();
        let answers = answers?;

        Ok(Message {
            header,
            questions,
            answers,
            ..Default::default()
        })
    }
}

#[test]
fn test_parser_decompress() {
    let message_bytes: &[u8] = &[
        144, 155, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, // header bytes
        3, 97, 98, 99, 17, 108, 111, 110, 103, 97, 115, 115, 100, 111, 109, 97, 105, 110, 110, 97,
        109, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, // question abc longassdomainname com
        3, 100, 101, 102, 192, 16, 0, 1, 0, 1, // question def jump
    ];

    let mut parser = DnsParser {
        packet: message_bytes.to_vec(),
        pos: 0,
    };

    parser.parse().unwrap();

    assert!(true);
}
