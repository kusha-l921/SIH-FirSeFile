// Linux-only io_uring helpers.
pub mod uring_reader;
pub use uring_reader::read_block;
