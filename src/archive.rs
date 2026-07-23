use std::io::{self, Read, Seek, SeekFrom};

use crate::encoding;
use crate::error::{EggError, EggResult};

// Signatures
const SIG_EGG_HEADER: u32 = 0x41474745;
const SIG_SPLIT_INFO: u32 = 0x24F5A262;
const SIG_SOLID_INFO: u32 = 0x24E5A060;
const SIG_FILE_HEADER: u32 = 0x0A8590E3;
const SIG_FILENAME: u32 = 0x0A8591AC;
const SIG_COMMENT: u32 = 0x04C63672;
const SIG_WINDOWS_FILE_INFO: u32 = 0x2C86950B;
const SIG_ENCRYPT_INFO: u32 = 0x08D1470F;
const SIG_BLOCK_HEADER: u32 = 0x02B50C13;
const SIG_DUMMY: u32 = 0x07463307;
const SIG_END_MARKER: u32 = 0x08E28222;
const SIG_SKIP: u32 = 0xFFFF0000;
const SIG_GLOBAL_ENCRYPT: u32 = 0x08D144A8;
const SIG_POSIX_FILE_INFO: u32 = 0x1EE922E5;

pub const ATTR_DIRECTORY: u8 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    Store,
    Deflate,
    Bzip2,
    Azo,
    Lzma,
    Unknown(u8),
}

impl CompressionMethod {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Store,
            1 => Self::Deflate,
            2 => Self::Bzip2,
            3 => Self::Azo,
            4 => Self::Lzma,
            n => Self::Unknown(n),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Store => "Store",
            Self::Deflate => "Deflate",
            Self::Bzip2 => "Bzip2",
            Self::Azo => "AZO",
            Self::Lzma => "LZMA",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl std::fmt::Display for CompressionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMethod {
    ZipCrypto,
    Aes128,
    Aes256,
    Lea128,
    Lea256,
    Unknown(u8),
}

impl EncryptionMethod {
    fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::ZipCrypto,
            1 => Self::Aes128,
            2 => Self::Aes256,
            5 => Self::Lea128,
            6 => Self::Lea256,
            n => Self::Unknown(n),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::ZipCrypto => "ZipCrypto",
            Self::Aes128 => "AES-128",
            Self::Aes256 => "AES-256",
            Self::Lea128 => "LEA-128",
            Self::Lea256 => "LEA-256",
            Self::Unknown(_) => "Unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptInfo {
    pub method: EncryptionMethod,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EggBlock {
    pub compression_method: CompressionMethod,
    pub uncompressed_size: u32,
    pub compressed_size: u32,
    pub crc32: u32,
    pub data_pos: u64,
}

#[derive(Debug, Clone)]
pub struct EggFileEntry {
    pub file_name: String,
    pub file_id: u32,
    pub uncompressed_size: u64,
    pub blocks: Vec<EggBlock>,
    pub encrypt_info: Option<EncryptInfo>,
    pub file_time: Option<u64>,
    pub file_attr: u8,
    /// File ID of the entry holding this entry's parent-path prefix, set when
    /// the filename uses the relative-path flag (bit 5). Resolved into
    /// `file_name` after all entries are parsed; `None` for absolute names.
    pub parent_id: Option<u32>,
}

impl EggFileEntry {
    pub fn is_directory(&self) -> bool {
        self.file_attr & ATTR_DIRECTORY != 0
    }
}

pub struct SplitInfo {
    pub prev_id: u32,
    pub next_id: u32,
}

pub struct EggArchive<R: Read + Seek> {
    pub reader: R,
    pub entries: Vec<EggFileEntry>,
    pub is_encrypted: bool,
    pub is_solid: bool,
    pub header_id: u32,
    pub split_info: Option<SplitInfo>,
}

impl<R: Read + Seek> EggArchive<R> {
    pub fn open(mut reader: R) -> EggResult<Self> {
        // Read EGG Header signature
        let sig = read_u32(&mut reader)?;
        if sig != SIG_EGG_HEADER {
            return Err(EggError::NotEggFile);
        }

        let _version = read_u16(&mut reader)?;
        let header_id = read_u32(&mut reader)?;
        let _reserved = read_u32(&mut reader)?;

        let mut is_solid = false;
        let mut split_info = None;
        let mut is_encrypted = false;
        let mut entries = Vec::new();

        // Parse prefix section until End Marker
        loop {
            let sig = read_u32(&mut reader)?;
            match sig {
                SIG_SPLIT_INFO => {
                    let (_flags, _size) = read_extra_field(&mut reader)?;
                    let prev_id = read_u32(&mut reader)?;
                    let next_id = read_u32(&mut reader)?;
                    split_info = Some(SplitInfo { prev_id, next_id });
                }
                SIG_SOLID_INFO => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                    is_solid = true;
                }
                SIG_SKIP => {
                    let (_flags, _size) = read_extra_field(&mut reader)?;
                    let _prev_id = read_u32(&mut reader)?;
                    let _next_id = read_u32(&mut reader)?;
                }
                SIG_GLOBAL_ENCRYPT => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_END_MARKER => break,
                _ => return Err(EggError::CorruptedFile),
            }
        }

        // Parse file entries
        loop {
            let sig = read_u32(&mut reader)?;
            match sig {
                SIG_FILE_HEADER => {
                    let entry = parse_file_entry(&mut reader, &mut is_encrypted)?;
                    entries.push(entry);
                }
                SIG_COMMENT => {
                    // Archive-level comment, skip it
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_DUMMY => {
                    let (_flags, size) = read_extra_field(&mut reader)?;
                    skip(&mut reader, size as u64)?;
                }
                SIG_END_MARKER => {
                    // In multi-volume archives, this may be a volume boundary
                    // rather than the true end. Peek at the next signature.
                    match read_u32(&mut reader) {
                        Ok(next)
                            if next == SIG_FILE_HEADER
                                || next == SIG_COMMENT
                                || next == SIG_DUMMY =>
                        {
                            reader.seek(SeekFrom::Current(-4))?;
                        }
                        Ok(_) => {
                            reader.seek(SeekFrom::Current(-4))?;
                            break;
                        }
                        Err(_) => break,
                    }
                }
                _ => return Err(EggError::CorruptedFile),
            }
        }

        resolve_relative_paths(&mut entries);

        Ok(EggArchive {
            reader,
            entries,
            is_encrypted,
            is_solid,
            header_id,
            split_info,
        })
    }
}

fn parse_file_entry<R: Read + Seek>(
    reader: &mut R,
    is_encrypted: &mut bool,
) -> EggResult<EggFileEntry> {
    let file_id = read_u32(reader)?;
    let uncompressed_size = read_u64(reader)?;

    let mut file_name = String::new();
    let mut file_time: Option<u64> = None;
    let mut file_attr: u8 = 0;
    let mut encrypt_info: Option<EncryptInfo> = None;
    let mut parent_id: Option<u32> = None;

    // Parse sub-headers until End Marker
    loop {
        let sig = read_u32(reader)?;
        match sig {
            SIG_FILENAME => {
                let (flags, size) = read_extra_field(reader)?;
                let mut remaining = size as usize;
                let use_area_code = flags & 0x10 != 0;
                let is_relative = flags & 0x20 != 0;
                let is_encrypted_name = flags & 0x08 != 0;

                let locale_code = if use_area_code {
                    let lc = read_u16(reader)?;
                    remaining = remaining.checked_sub(2).ok_or(EggError::CorruptedFile)?;
                    Some(lc)
                } else {
                    None
                };

                // Bit 5: relative path. Keep the parent File ID so the full path
                // can be reconstructed from the referenced entry after parsing.
                if is_relative {
                    parent_id = Some(read_u32(reader)?);
                    remaining = remaining.checked_sub(4).ok_or(EggError::CorruptedFile)?;
                }

                let name_buf = read_exact_capped(reader, remaining)?;

                // Bit 3: the filename bytes are encrypted. Decryption needs the
                // password, which is not available at parse time, and no known
                // producer emits this (the spec notes flags are always 0x00 in
                // practice), so the name is decoded best-effort as-is.
                let _ = is_encrypted_name;

                let decoded = encoding::decode_filename(flags, locale_code, &name_buf);
                file_name = encoding::normalize_path(&decoded);
            }
            SIG_COMMENT => {
                let (_flags, size) = read_extra_field(reader)?;
                skip(reader, size as u64)?;
            }
            SIG_WINDOWS_FILE_INFO => {
                let (_flags, size) = read_extra_field(reader)?;
                // Read the fixed 9 bytes (time + attr) but honor the declared
                // field length so a crafted size can't desync later parsing.
                if (size as usize) < 9 {
                    return Err(EggError::CorruptedFile);
                }
                file_time = Some(read_u64(reader)?);
                file_attr = read_u8(reader)?;
                skip(reader, size as u64 - 9)?;
            }
            SIG_POSIX_FILE_INFO => {
                let (_flags, size) = read_extra_field(reader)?;
                skip(reader, size as u64)?;
            }
            SIG_ENCRYPT_INFO => {
                let (_flags, size) = read_extra_field(reader)?;
                // At least the 1-byte method must be present; a zero size would
                // otherwise read the following signature's byte as the method.
                if size == 0 {
                    return Err(EggError::CorruptedFile);
                }
                let method_byte = read_u8(reader)?;
                let data_len = (size as usize) - 1;
                let data = read_exact_capped(reader, data_len)?;

                let method = EncryptionMethod::from_byte(method_byte);
                if let EncryptionMethod::Unknown(n) = method {
                    return Err(EggError::UnsupportedEncryption(n));
                }
                *is_encrypted = true;
                encrypt_info = Some(EncryptInfo { method, data });
            }
            SIG_END_MARKER => break,
            _ => return Err(EggError::CorruptedFile),
        }
    }

    // Parse blocks
    let mut blocks = Vec::new();
    loop {
        let sig = read_u32(reader)?;
        match sig {
            SIG_BLOCK_HEADER => {
                let block = parse_block(reader)?;
                blocks.push(block);
            }
            SIG_COMMENT | SIG_FILE_HEADER | SIG_END_MARKER | SIG_DUMMY => {
                // Unread the signature
                reader.seek(SeekFrom::Current(-4))?;
                break;
            }
            _ => return Err(EggError::CorruptedFile),
        }
    }

    Ok(EggFileEntry {
        file_name,
        file_id,
        uncompressed_size,
        blocks,
        encrypt_info,
        file_time,
        file_attr,
        parent_id,
    })
}

/// Resolve relative-path entries (filename flag bit 5) by prepending the path of
/// the entry referenced by `parent_id`. Done once, after all entries are parsed,
/// so both backward and forward references resolve. Deeper chains are resolved a
/// single level (nested relative parents are rare and never seen in practice).
fn resolve_relative_paths(entries: &mut [EggFileEntry]) {
    use std::collections::HashMap;
    let by_id: HashMap<u32, usize> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.file_id, i))
        .collect();

    let resolved: Vec<Option<String>> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let pid = e.parent_id?;
            let &pi = by_id.get(&pid)?;
            if pi == i {
                return None;
            }
            let prefix = entries[pi].file_name.trim_end_matches('/');
            if prefix.is_empty() {
                None
            } else {
                Some(format!("{prefix}/{}", e.file_name))
            }
        })
        .collect();

    for (entry, new_name) in entries.iter_mut().zip(resolved) {
        if let Some(name) = new_name {
            entry.file_name = name;
        }
    }
}

fn parse_block<R: Read + Seek>(reader: &mut R) -> EggResult<EggBlock> {
    let method_byte = read_u8(reader)?;
    let _hint = read_u8(reader)?;
    let uncompressed_size = read_u32(reader)?;
    let compressed_size = read_u32(reader)?;
    let crc32 = read_u32(reader)?;

    // End Marker must follow
    let end_sig = read_u32(reader)?;
    if end_sig != SIG_END_MARKER {
        return Err(EggError::CorruptedFile);
    }

    let data_pos = reader.stream_position()?;

    // Skip over compressed data
    skip(reader, compressed_size as u64)?;

    Ok(EggBlock {
        compression_method: CompressionMethod::from_byte(method_byte),
        uncompressed_size,
        compressed_size,
        crc32,
        data_pos,
    })
}

/// Read the extra field prefix: flags byte + size (u16 or u32).
fn read_extra_field<R: Read>(reader: &mut R) -> EggResult<(u8, u32)> {
    let flags = read_u8(reader)?;
    let size = if flags & 0x01 != 0 {
        read_u32(reader)?
    } else {
        read_u16(reader)? as u32
    };
    Ok((flags, size))
}

fn skip<R: Read + Seek>(reader: &mut R, n: u64) -> EggResult<()> {
    reader.seek(SeekFrom::Current(n as i64))?;
    Ok(())
}

/// Read exactly `n` bytes, but grow the buffer from the data actually present
/// rather than pre-allocating `n`. A crafted header declaring a huge size thus
/// fails with a short read instead of triggering a multi-gigabyte allocation.
fn read_exact_capped<R: Read>(reader: &mut R, n: usize) -> EggResult<Vec<u8>> {
    let mut buf = Vec::new();
    let read = (&mut *reader).take(n as u64).read_to_end(&mut buf)?;
    if read != n {
        return Err(EggError::CorruptedFile);
    }
    Ok(buf)
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u16<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_exact_capped_exact() {
        let mut c = Cursor::new(vec![1u8, 2, 3, 4]);
        assert_eq!(read_exact_capped(&mut c, 4).unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn read_exact_capped_short_read_errors() {
        // A huge declared size with little data behind it must error, not
        // attempt to allocate the declared amount.
        let mut c = Cursor::new(vec![1u8, 2, 3]);
        assert!(matches!(
            read_exact_capped(&mut c, 1 << 30),
            Err(EggError::CorruptedFile)
        ));
    }
}
