extern crate ntfs_upcase;
extern crate unicode_normalization;

use std::default::Default;
use ntfs_upcase::NtfsUpcaseTable;
use unicode_normalization::char::compose;
use unicode_normalization::UnicodeNormalization;


pub struct NtfsPathCollator {
	pub upcase: NtfsUpcaseTable,
}


pub enum NtfsPathCollatorError {
	DecodeUtf16Error(std::char::DecodeUtf16Error)
}


type Result<T> = std::result::Result<T, NtfsPathCollatorError>;


impl NtfsPathCollator {
	pub fn normalize_utf16_path(&self, p: &str) -> Result<String> {
		let upcased = p
			.encode_utf16()
			.map(|c: u16| self.upcase.map_utf16_char(c));
		let upcased_decode: String = std::char::decode_utf16(upcased)
			.map(|e| e.map_err(NtfsPathCollatorError::DecodeUtf16Error))
			.collect::<Result<String>>()?;
		Ok(upcased_decode.nfc().collect())
	}
}
