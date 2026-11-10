//! Just enough protobuf decoding for Xray's geodata files.

use anyhow::{bail, Result};

pub enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let Some((&byte, rest)) = self.buf.split_first() else {
                bail!("truncated protobuf varint");
            };
            self.buf = rest;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("protobuf varint too long")
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            bail!("truncated protobuf field");
        }
        let (head, rest) = self.buf.split_at(n);
        self.buf = rest;
        Ok(head)
    }

    /// Next `(field number, value)`; fixed-size fields are skipped.
    pub fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>> {
        loop {
            if self.buf.is_empty() {
                return Ok(None);
            }
            let key = self.varint()?;
            let field = (key >> 3) as u32;
            match key & 7 {
                0 => return Ok(Some((field, Value::Varint(self.varint()?)))),
                2 => {
                    let len = self.varint()? as usize;
                    return Ok(Some((field, Value::Bytes(self.take(len)?))));
                }
                1 => {
                    self.take(8)?;
                }
                5 => {
                    self.take(4)?;
                }
                other => bail!("unsupported protobuf wire type {other}"),
            }
        }
    }
}
