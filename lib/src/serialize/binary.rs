use std::io::Write;

pub trait BinEncodable {
    /// Write the type to the stream
    fn emit(&self, encoder: &mut BinEncoder<'_>) -> Result<(), String>;

    /// Returns the object in binary form
    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::<u8>::new();
        {
            let mut encoder = BinEncoder::new(&mut bytes);
            self.emit(&mut encoder)?;
        }

        Ok(bytes)
    }
}

pub struct BinEncoder<'a> {
    offset: usize,
    buffer: &'a mut Vec<u8>,
    name_pointers: Vec<(usize, Vec<u8>)>,
    canonical_names: bool,
}

impl<'a> BinEncoder<'a> {
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self::with_offset(buf, 0)
    }

    pub fn with_offset(buf: &'a mut Vec<u8>, offset: u32) -> Self {
        if buf.capacity() < 512 {
            let reserve = 512 - buf.capacity();
            buf.reserve(reserve);
        }

        BinEncoder {
            offset: offset as usize,
            buffer: buf,
            name_pointers: Vec::new(),
            canonical_names: false,
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn set_canonical_names(&mut self, canonical_names: bool) {
        self.canonical_names = canonical_names;
    }

    pub fn emit_character_data<S: AsRef<[u8]>>(&mut self, char_data: S) -> Result<(), String> {
        let char_bytes = char_data.as_ref();
        if char_bytes.len() > 255 {
            return Err("Character Data too long".into());
        }

        self.emit_character_data_unrestricted(char_data)
    }

    pub fn emit_character_data_unrestricted<S: AsRef<[u8]>>(
        &mut self,
        data: S,
    ) -> Result<(), String> {
        // first the length is written
        let data = data.as_ref();
        self.emit(data.len() as u8)?;
        self.write_slice(data)
    }

    pub fn slice_of(&self, start: usize, end: usize) -> &[u8] {
        assert!(start < self.offset);
        assert!(end <= self.buffer.len());
        &self.buffer[start..end]
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn trim(&mut self) {
        let offset = self.offset;
        self.buffer.truncate(offset);
        self.name_pointers.retain(|&(start, _)| start < offset);
    }

    pub fn get_label_pointer(&self, start: usize, end: usize) -> Option<u16> {
        let search = self.slice_of(start, end);

        for (match_start, matcher) in &self.name_pointers {
            if matcher.as_slice() == search {
                assert!(match_start <= &(u16::MAX as usize));
                return Some(*match_start as u16);
            }
        }

        None
    }

    pub fn store_label_pointer(&mut self, start: usize, end: usize) {
        assert!(start <= (u16::MAX as usize));
        assert!(end <= (u16::MAX as usize));
        assert!(start <= end);
        if self.offset < 0x3FFF_usize {
            self.name_pointers
                .push((start, self.slice_of(start, end).to_vec())); // the next char will be at the len() location
        }
    }

    pub fn emit_u16(&mut self, data: u16) -> Result<(), String> {
        self.write_slice(&data.to_be_bytes())
    }

    pub fn emit_u32(&mut self, data: u32) -> Result<(), String> {
        self.write_slice(&data.to_be_bytes())
    }

    fn write_slice(&mut self, data: &[u8]) -> Result<(), String> {
        self.buffer.write_all(data).unwrap(); // TODO: Error handling
        self.offset += data.len();
        Ok(())
    }

    pub fn emit(&mut self, b: u8) -> Result<(), String> {
        self.buffer.write_all(&[b]).unwrap(); // TODO: Error handling
        self.offset += 1;
        Ok(())
    }
}
