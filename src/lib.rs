use std::fmt::Debug;
#[cfg(test)]
use std::io::Cursor;
use ntfs_upcase::NtfsUpcaseTable;
use unicode_normalization::UnicodeNormalization;


pub struct NtfsPathCollator {
	pub upcase: NtfsUpcaseTable,
}


#[derive(Debug)]
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

#[test]
fn test_normalize_utf16_path() {
	let mut upcase_ntfs3g = Cursor::new(ntfs_upcase::UPCASEDATA_NTFS3G);
	let mut upcaseinfo_ntfs3g = Cursor::new(ntfs_upcase::UPCASEINFO_NTFS3G);
	let upcase = NtfsUpcaseTable::try_parse_upcase_and_info_files(&mut upcase_ntfs3g, &mut upcaseinfo_ntfs3g).unwrap();
	let collator = NtfsPathCollator { upcase };

	assert_eq!(collator.normalize_utf16_path("Lorem ipsum").unwrap(), "LOREM IPSUM");
	assert_eq!(collator.normalize_utf16_path("Wacław Sierpiński").unwrap(), "WACŁAW SIERPIŃSKI");

	// UAX #15, fig. 3 (https://unicode.org/reports/tr15/)
	assert_eq!(collator.normalize_utf16_path("\u{212B}").unwrap(), "\u{00C5}");
	assert_eq!(collator.normalize_utf16_path("\u{2126}").unwrap(), "\u{03A9}");

	// UAX #15, fig. 5
	assert_eq!(collator.normalize_utf16_path("\u{1E69}").unwrap(), "\u{1E68}");
	assert_eq!(collator.normalize_utf16_path("\u{1E0B}\u{0323}").unwrap(), "\u{1E0C}\u{0307}");
	assert_eq!(collator.normalize_utf16_path("\u{0071}\u{0307}\u{0323}").unwrap(), "\u{0051}\u{0323}\u{0307}");
}
