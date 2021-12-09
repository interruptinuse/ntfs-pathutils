//! NTFS: $UpCase table, $UpCase:$Info table metadata
//! =================================================
//!
//! Per the [asmhackers][asmhackers] documentation: The $UpCase file itself
//! is a simple list of all Unicode characters in uppercase.  An input Unicode
//! code point N corresponds to N-th word (2-byte LSB value) of the file.
//!
//! [asmhackers]: http://bos.asmhackers.net/docs/filesystems/ntfs/upcase.html


extern crate lazy_static;
extern crate derive_more;
extern crate byteorder;

use std::error::Error;
use std::fmt::Debug;
use std::io::Read;
use std::vec::Vec;
use std::io::Cursor;
use lazy_static::lazy_static;
use derive_more::Display;
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};


use self::NtfsUpcaseTableError::{
	UnexpectedUpcaseInfoFileSize,
	UpcaseInfoCrcMismatch,
};


pub const CRC64_POLY: u64 = 0x9a6c9329ac4bc9b5;
pub const CRC64_XOROUT: u64 = 0xffffffffffffffff;
pub const DEFAULT_TABLE_SIZE_CHARS: usize = 65536;
pub const CRC64_TABLE: [u64; 256] = gen_crc_table();
lazy_static! {
	pub static ref UPCASE_NTFS3G: NtfsUpcaseTable
		= NtfsUpcaseTable::try_parse_upcase_and_info_files(
			&mut Cursor::new(include_bytes!("upcase_NTFS3G.bin")),
			&mut Cursor::new(include_bytes!("upcaseinfo_NTFS3G.bin"))).unwrap();
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

	while let Ok(codepoint) = upcase.read_u16::<byteorder::LittleEndian>() {
		crc = crc64_digest(crc, &codepoint.to_le_bytes());
		chars.push(codepoint);
	};

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
	let mut upcase_file = Cursor::new(vec![0u8, 0, 1, 0, 2, 0]);
	let table = upcasetable_try_parse_upcase_file(&mut upcase_file).unwrap();
	assert_eq!(table.chars, vec![0u16, 1, 2]);
}

#[test]
fn test_try_parse_upcase_and_info_files() {
	let mut upcase_mswin10 = Cursor::new(include_bytes!("upcase_NTFS3G.bin"));
	let mut upcaseinfo_mswin10 = Cursor::new(include_bytes!("upcaseinfo_NTFS3G.bin"));

	let table = upcasetable_try_parse_upcase_and_info_files(&mut upcase_mswin10, &mut upcaseinfo_mswin10).unwrap();
	let info = table.info.unwrap();
	assert_eq!(info.len,       32);
	assert_eq!(info.osmajor,   0);
	assert_eq!(info.osminor,   0);
	assert_eq!(info.build,     0);
	assert_eq!(info.packmajor, 0);
	assert_eq!(info.packminor, 0);
	assert_eq!(table.file_crc, 0xdadc7e776b1b690c);
}
