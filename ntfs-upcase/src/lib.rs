//! NTFS: $UpCase table, $UpCase:$Info table metadata
//! =================================================
//!
//! Per the [asmhackers][asmhackers] documentation: The $UpCase file itself
//! is a simple list of all Unicode characters in uppercase.  An input Unicode
//! code point N corresponds to N-th word (2-byte LSB value) of the file.
//!
//! [asmhackers]: http://bos.asmhackers.net/docs/filesystems/ntfs/upcase.html


use std::error::Error;
use std::fmt::Debug;
use std::io::Read;
use std::vec::Vec;
#[cfg(any(feature = "lazy_static", test))]
use std::io::Cursor;
#[cfg(feature = "lazy_static")]
use lazy_static::lazy_static;
use derive_more::Display;
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};


use self::NtfsUpcaseTableError::*;


pub const CRC64_POLY: u64 = 0x9a6c9329ac4bc9b5;
pub const CRC64_XOROUT: u64 = 0xffffffffffffffff;
pub const DEFAULT_TABLE_SIZE_CHARS: usize = 65536;
pub const CRC64_TABLE: [u64; 256] = gen_crc_table();
pub const UPCASEDATA_NTFS3G: &[u8] = include_bytes!("upcase_NTFS3G.bin");
pub const UPCASEINFO_NTFS3G: &[u8] = include_bytes!("upcaseinfo_NTFS3G.bin");

#[cfg(feature = "lazy_static")]
lazy_static! {
	pub static ref UPCASE_NTFS3G: NtfsUpcaseTable
		= NtfsUpcaseTable::try_parse_upcase_and_info_files(
			&mut Cursor::new(UPCASEDATA_NTFS3G),
			&mut Cursor::new(UPCASEINFO_NTFS3G)).unwrap();
}


#[derive(Debug, Clone)]
pub struct NtfsUpcaseTable {
	pub chars: Vec<u16>,
	pub file_crc: u64,
	pub info: Option<NtfsUpcaseTableInfo>
}


#[derive(Debug, Clone)]
pub struct NtfsUpcaseTableInfo {
	pub len:       u32,
	pub crc:       u64,
	pub osmajor:   u32,
	pub osminor:   u32,
	pub build:     u32,
	pub packmajor: u16,
	pub packminor: u16
}


#[derive(Debug, Display)]
pub enum NtfsUpcaseTableError {
	#[display(fmt = "UpcaseFileUnexpectedlyLarge: retrieved chars = {:?}", _0)]
	UpcaseFileUnexpectedlyLarge(Vec<u16>),

	#[display(fmt = "UpcaseFileSizeNotMultipleOfWordSize: retrieved chars = {:?}", _0)]
	UpcaseFileSizeNotMultipleOfWordSize(Vec<u16>),

	#[display(fmt = "UnexpectedUpcaseInfoFileSize: {:?}", _0)]
	UnexpectedUpcaseInfoFileSize(std::io::Error),
	UnexpectedUpcaseInfoFileError(std::io::Error),
	#[display(fmt = "UpcaseInfoCrcMismatch: INFO CRC64 = {:#018x}, computed CRC64 = {:#018x}", _0, _1)]
	UpcaseInfoCrcMismatch(u64, u64, NtfsUpcaseTable),
}


impl Error for NtfsUpcaseTableError { }

type Result<T> = std::result::Result<T, NtfsUpcaseTableError>;


impl NtfsUpcaseTable {
	pub fn try_parse_upcase_file<U: Read>(upcase: &mut U) -> Result<Self> {
		upcasetable_try_parse_upcase_file(upcase)
	}


	pub fn try_parse_upcase_and_info_files<U: Read, I: Read>(upcase: &mut U, info: &mut I) -> Result<Self> {
		upcasetable_try_parse_upcase_and_info_files(upcase, info)
	}


	pub fn map_utf16_char(&self, c: u16) -> u16 {
		*self.chars.get(c as usize).unwrap_or(&c)
	}
}


// This is the exact same table as in the ECMA-182 CRC-64 algorithm (implemented
// by the crc and crc_catalog crates).  However, I didn't manage to make
// CRC_64_ECMA_182 work.  Idk.  CRC implementations don't seem to be exceedingly
// consistent.
const fn gen_crc_table() -> [u64; 256] {
	let mut table: [u64; 256] = [0; 256];

	let mut c: u64;

	let mut i = 0;

	while i < 256 {
		c = i;

		let mut j = 0;

		while j < 8 {
			c = if c & 1 == 1 { CRC64_POLY ^ (c >> 1) } else { c >> 1 };
			j += 1;
		}

		table[i as usize] = c;

		i += 1;
	}

	table
}


fn crc64_digest(crc: u64, data: &[u8]) -> u64 {
	let mut crc = crc;
	crc ^= CRC64_XOROUT;

	for &v in data {
		crc = CRC64_TABLE[((crc as u8) ^ v) as usize] ^ (crc >> 8);
	};

	crc ^ CRC64_XOROUT
}


fn upcasetable_try_parse_upcase_file<U: Read>(upcase: &mut U) -> Result<NtfsUpcaseTable> {
	let mut chars: Vec<u16> = Vec::with_capacity(DEFAULT_TABLE_SIZE_CHARS);
	let mut crc = 0u64;

	let mut index = 0u32;

	while let Ok(codepoint) = upcase.read_u16::<byteorder::LittleEndian>() {
		if index > u16::MAX.into() {
			return Err(UpcaseFileUnexpectedlyLarge(chars));
		}

		if codepoint == 0xFFFF {
			if let Ok(n_id) = upcase.read_u16::<byteorder::LittleEndian>() {
				for _ in 0..n_id {
					crc = crc64_digest(crc, &index.to_le_bytes());

					let codepoint = index.try_into();
					if let Ok(codepoint) = codepoint {
						chars.push(codepoint);
						index += 1;
					} else {
						return Err(UpcaseFileUnexpectedlyLarge(chars));
					}
				}

				continue;
			};
		}

		crc = crc64_digest(crc, &codepoint.to_le_bytes());
		chars.push(codepoint);
		index += 1;
	};

	if upcase.read_u8().is_ok() {
		return if index >= u16::MAX.into() {
			Err(UpcaseFileUnexpectedlyLarge(chars))
		} else {
			Err(UpcaseFileSizeNotMultipleOfWordSize(chars))
		}
	}

	Ok(NtfsUpcaseTable {
		chars,
		file_crc: crc,
		info: None
	})
}


fn upcasetable_try_parse_upcase_and_info_files<U: Read, I: Read>(upcase: &mut U, info: &mut I) -> Result<NtfsUpcaseTable> {
	let mut table = upcasetable_try_parse_upcase_file(upcase)?;
	let mut upcaseinfo_file = [0u8; 32];
	info
		.read_exact(&mut upcaseinfo_file)
		.map_err(UnexpectedUpcaseInfoFileSize)?;

	let ui_read_u16 = |f, t| LittleEndian::read_u16(&upcaseinfo_file[f..t]);
	let ui_read_u32 = |f, t| LittleEndian::read_u32(&upcaseinfo_file[f..t]);
	let ui_read_u64 = |f, t| LittleEndian::read_u64(&upcaseinfo_file[f..t]);

	let upcaseinfo = NtfsUpcaseTableInfo {
		len:       ui_read_u32(0x00, 0x04),
		crc:       ui_read_u64(0x08, 0x10),
		osmajor:   ui_read_u32(0x10, 0x14),
		osminor:   ui_read_u32(0x14, 0x18),
		build:     ui_read_u32(0x18, 0x1c),
		packmajor: ui_read_u16(0x1c, 0x1e),
		packminor: ui_read_u16(0x1e, 0x20),
	};

	table.info = Some(upcaseinfo.clone());

	if upcaseinfo.crc != table.file_crc {
		return Err(UpcaseInfoCrcMismatch(upcaseinfo.crc, table.file_crc, table));
	};

	Ok(table)
}


#[test]
fn test_try_parse_upcase_file() {
	macro_rules! assert_data_eq_chars {
		($data:expr, $chars:expr) => {
			let mut upcase_file = Cursor::new($data);
			let table = upcasetable_try_parse_upcase_file(&mut upcase_file).unwrap();
			assert_eq!(table.chars, $chars);
		}
	}

	// Naive table
	assert_data_eq_chars!(
		vec![0u8, 0, 1, 0, 2, 0],
		vec![  0u16,    1,    2]);

	// Compressed table
	assert_data_eq_chars!(
		vec![0xFFu8, 0xFF, 7, 0],
		vec![0u16, 1, 2, 3, 4, 5, 6]);

	// Compressed table, again
	assert_data_eq_chars!(
		vec![0u8, 0, 0xFF, 0xFF, 4, 0, 0x05, 0x00],
		vec![0u16,         1, 2, 3, 4,          5]);

	// Table not compressed (but has an FFFF at the end)
	assert_data_eq_chars!(
		vec![0u8, 0, 1, 0, 0xFF, 0xFF],
		vec![  0u16,    1,     0xFFFF]);

	// Table of a size not multiple of 2 bytes
	let mut upcase_file = Cursor::new(vec![0u8]);
	assert!(matches!(upcasetable_try_parse_upcase_file(&mut upcase_file), Err(UpcaseFileSizeNotMultipleOfWordSize(_))));

	// File too large
	const BIG_DATA_SIZE: usize = DEFAULT_TABLE_SIZE_CHARS * 2 + 1;
	let mut loadsadata = Cursor::new([0u8; BIG_DATA_SIZE]);
	assert!(matches!(upcasetable_try_parse_upcase_file(&mut loadsadata), Err(UpcaseFileUnexpectedlyLarge(_))));

	let mut loadsadata = Cursor::new([0u8; BIG_DATA_SIZE+1]);
	assert!(matches!(upcasetable_try_parse_upcase_file(&mut loadsadata), Err(UpcaseFileUnexpectedlyLarge(_))));

	// https://www.ntfs.com/exfat-upcase-table.htm
	let mut first_mandatory_128_entries: Cursor<Vec<u8>> = Cursor::new(vec![
		0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
		0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00,
		0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00,
		0x0C, 0x00, 0x0D, 0x00, 0x0E, 0x00, 0x0F, 0x00,
		0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x00,
		0x14, 0x00, 0x15, 0x00, 0x16, 0x00, 0x17, 0x00,
		0x18, 0x00, 0x19, 0x00, 0x1A, 0x00, 0x1B, 0x00,
		0x1C, 0x00, 0x1D, 0x00, 0x1E, 0x00, 0x1F, 0x00,
		0x20, 0x00, 0x21, 0x00, 0x22, 0x00, 0x23, 0x00,
		0x24, 0x00, 0x25, 0x00, 0x26, 0x00, 0x27, 0x00,
		0x28, 0x00, 0x29, 0x00, 0x2A, 0x00, 0x2B, 0x00,
		0x2C, 0x00, 0x2D, 0x00, 0x2E, 0x00, 0x2F, 0x00,
		0x30, 0x00, 0x31, 0x00, 0x32, 0x00, 0x33, 0x00,
		0x34, 0x00, 0x35, 0x00, 0x36, 0x00, 0x37, 0x00,
		0x38, 0x00, 0x39, 0x00, 0x3A, 0x00, 0x3B, 0x00,
		0x3C, 0x00, 0x3D, 0x00, 0x3E, 0x00, 0x3F, 0x00,
		0x40, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00,
		0x44, 0x00, 0x45, 0x00, 0x46, 0x00, 0x47, 0x00,
		0x48, 0x00, 0x49, 0x00, 0x4A, 0x00, 0x4B, 0x00,
		0x4C, 0x00, 0x4D, 0x00, 0x4E, 0x00, 0x4F, 0x00,
		0x50, 0x00, 0x51, 0x00, 0x52, 0x00, 0x53, 0x00,
		0x54, 0x00, 0x55, 0x00, 0x56, 0x00, 0x57, 0x00,
		0x58, 0x00, 0x59, 0x00, 0x5A, 0x00, 0x5B, 0x00,
		0x5C, 0x00, 0x5D, 0x00, 0x5E, 0x00, 0x5F, 0x00,
		0x60, 0x00, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00,
		0x44, 0x00, 0x45, 0x00, 0x46, 0x00, 0x47, 0x00,
		0x48, 0x00, 0x49, 0x00, 0x4A, 0x00, 0x4B, 0x00,
		0x4C, 0x00, 0x4D, 0x00, 0x4E, 0x00, 0x4F, 0x00,
		0x50, 0x00, 0x51, 0x00, 0x52, 0x00, 0x53, 0x00,
		0x54, 0x00, 0x55, 0x00, 0x56, 0x00, 0x57, 0x00,
		0x58, 0x00, 0x59, 0x00, 0x5A, 0x00, 0x7B, 0x00,
		0x7C, 0x00, 0x7D, 0x00, 0x7E, 0x00, 0x7F, 0x00,
	]);
	let mut first_mandatory_128_entries_compressed: Cursor<Vec<u8>> = Cursor::new(vec![
		0xFF, 0xFF, 0x61, 0x00, 0x41, 0x00, 0x42, 0x00,
		0x43, 0x00, 0x44, 0x00, 0x45, 0x00, 0x46, 0x00,
		0x47, 0x00, 0x48, 0x00, 0x49, 0x00, 0x4A, 0x00,
		0x4B, 0x00, 0x4C, 0x00, 0x4D, 0x00, 0x4E, 0x00,
		0x4F, 0x00, 0x50, 0x00, 0x51, 0x00, 0x52, 0x00,
		0x53, 0x00, 0x54, 0x00, 0x55, 0x00, 0x56, 0x00,
		0x57, 0x00, 0x58, 0x00, 0x59, 0x00, 0x5A, 0x00,
		0xFF, 0xFF, 0x05, 0x00,
	]);
	let upcase_128   = upcasetable_try_parse_upcase_file(&mut first_mandatory_128_entries).unwrap();
	let upcase_128_c = upcasetable_try_parse_upcase_file(&mut first_mandatory_128_entries_compressed).unwrap();
	assert_eq!(upcase_128.chars, upcase_128_c.chars);
}

#[test]
fn test_try_parse_upcase_and_info_files() {
	let mut upcase_mswin10 = Cursor::new(UPCASEDATA_NTFS3G);
	let mut upcaseinfo_mswin10 = Cursor::new(UPCASEINFO_NTFS3G);

	let table = upcasetable_try_parse_upcase_and_info_files(&mut upcase_mswin10, &mut upcaseinfo_mswin10).unwrap();
	let info = table.info.unwrap();
	assert_eq!(info.len,       32);
	assert_eq!(info.osmajor,   0);
	assert_eq!(info.osminor,   0);
	assert_eq!(info.build,     0);
	assert_eq!(info.packmajor, 0);
	assert_eq!(info.packminor, 0);
	assert_eq!(table.file_crc, 0xdadc7e776b1b690c);
	assert_eq!(table.chars.len(), 65536);
}
