#[derive(Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub offset: u64,
    pub data: Vec<u8>,
}

impl Block {
    pub fn new(id: u64, offset: u64, data: Vec<u8>) -> Self {
        Self { id, offset, data }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
}
