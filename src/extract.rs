use std::fs;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::aes_ctr::AesCtrDecryptor;
use crate::archive::{CompressionMethod, EggArchive, EggBlock, EggFileEntry, EncryptionMethod};
use crate::crypto::{Decryptor, ZipCrypto};
use crate::decompress;
use crate::error::{EggError, EggResult};
use crate::lea::LeaCtrDecryptor;

/// A file's decryptor plus, for AES/LEA, the material needed to verify the
/// WinZip AE-2 HMAC-SHA1 authentication footer.
struct FileCrypto {
    decryptor: Box<dyn Decryptor>,
    auth: Option<AuthInfo>,
}

struct AuthInfo {
    /// PBKDF2-derived HMAC key.
    key: Vec<u8>,
    /// Stored 10-byte authentication footer (truncated HMAC-SHA1 tag).
    tag: Vec<u8>,
}

/// Verify the AE-2 authentication footer: HMAC-SHA1(auth_key, ciphertext) over
/// all of the file's encrypted block bytes, truncated to the stored 10 bytes.
fn verify_hmac<R: Read + Seek>(
    reader: &mut R,
    entry: &EggFileEntry,
    auth: &AuthInfo,
) -> EggResult<()> {
    let mut mac = <Hmac<Sha1>>::new_from_slice(&auth.key).map_err(|_| EggError::CorruptedFile)?;
    let mut buf = [0u8; 8192];
    for block in &entry.blocks {
        reader.seek(SeekFrom::Start(block.data_pos))?;
        let mut remaining = block.compressed_size as usize;
        while remaining > 0 {
            let n = remaining.min(buf.len());
            reader.read_exact(&mut buf[..n])?;
            mac.update(&buf[..n]);
            remaining -= n;
        }
    }
    let computed = mac.finalize().into_bytes();
    if auth.tag.len() != 10 || computed.len() < 10 || computed[..10] != auth.tag[..] {
        return Err(EggError::AuthenticationFailed);
    }
    Ok(())
}

/// Join an archive entry name onto `dest` safely, rejecting any attempt to
/// escape the destination directory (`..`, absolute paths, Windows drive/UNC
/// prefixes). The path is rebuilt from `Normal` components only, so the result
/// is always contained within `dest`.
fn safe_join(dest: &Path, name: &str) -> EggResult<PathBuf> {
    let mut out = dest.to_path_buf();
    for comp in Path::new(name).components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(EggError::PathTraversal(name.to_string()));
            }
        }
    }
    Ok(out)
}

/// The 10-byte AE-2 authentication footer follows salt + 2-byte verifier in the
/// Encrypt Info data. Returns None if the archive omitted it (older layout).
fn auth_footer(data: &[u8], salt_size: usize) -> Option<Vec<u8>> {
    let start = salt_size + 2;
    data.get(start..start + 10).map(<[u8]>::to_vec)
}

fn setup_decryptor(entry: &EggFileEntry, password: Option<&str>) -> EggResult<Option<FileCrypto>> {
    let ei = match entry.encrypt_info {
        Some(ref ei) => ei,
        None => return Ok(None),
    };
    let pwd = password.ok_or(EggError::PasswordNotSet)?;

    let build_aes = |salt_size: usize, mode: u8| -> EggResult<FileCrypto> {
        if ei.data.len() < salt_size + 2 {
            return Err(EggError::CorruptedFile);
        }
        let salt = &ei.data[..salt_size];
        let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
        let dec = AesCtrDecryptor::new(mode, pwd, salt, &verifier)?;
        let auth = auth_footer(&ei.data, salt_size).map(|tag| AuthInfo {
            key: dec.auth_key().to_vec(),
            tag,
        });
        Ok(FileCrypto {
            decryptor: Box::new(dec),
            auth,
        })
    };

    let build_lea = |salt_size: usize, mode: u8| -> EggResult<FileCrypto> {
        if ei.data.len() < salt_size + 2 {
            return Err(EggError::CorruptedFile);
        }
        let salt = &ei.data[..salt_size];
        let verifier: [u8; 2] = ei.data[salt_size..salt_size + 2].try_into().unwrap();
        let dec = LeaCtrDecryptor::new(mode, pwd, salt, &verifier)?;
        let auth = auth_footer(&ei.data, salt_size).map(|tag| AuthInfo {
            key: dec.auth_key().to_vec(),
            tag,
        });
        Ok(FileCrypto {
            decryptor: Box::new(dec),
            auth,
        })
    };

    match ei.method {
        EncryptionMethod::ZipCrypto => {
            let mut zc = ZipCrypto::new(pwd.as_bytes());
            if ei.data.len() < 16 {
                return Err(EggError::CorruptedFile);
            }
            let verify: [u8; 12] = ei.data[..12].try_into().unwrap();
            let stored_crc = u32::from_le_bytes(ei.data[12..16].try_into().unwrap());
            if !zc.check_password(&verify, stored_crc) {
                return Err(EggError::InvalidPassword);
            }
            Ok(Some(FileCrypto {
                decryptor: Box::new(zc),
                auth: None,
            }))
        }
        EncryptionMethod::Aes128 => Ok(Some(build_aes(8, 1)?)),
        EncryptionMethod::Aes256 => Ok(Some(build_aes(16, 3)?)),
        EncryptionMethod::Lea128 => Ok(Some(build_lea(8, 1)?)),
        EncryptionMethod::Lea256 => Ok(Some(build_lea(16, 3)?)),
        EncryptionMethod::Unknown(n) => Err(EggError::UnsupportedEncryption(n)),
    }
}

/// Check `password` against the archive's encryption by verifying it on the
/// first encrypted entry. Returns `Ok(false)` for a wrong password, `Ok(true)`
/// if it matches or nothing is encrypted. Used to validate an interactively
/// prompted password before extraction begins.
pub fn verify_password(entries: &[EggFileEntry], password: &str) -> EggResult<bool> {
    for entry in entries {
        if entry.encrypt_info.is_some() {
            return match setup_decryptor(entry, Some(password)) {
                Ok(_) => Ok(true),
                Err(EggError::InvalidPassword) => Ok(false),
                Err(e) => Err(e),
            };
        }
    }
    Ok(true)
}

pub fn extract_entry<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    entry: &EggFileEntry,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> EggResult<()> {
    let target = safe_join(dest_dir, &entry.file_name)?;

    if entry.is_directory() {
        if !pipe_mode {
            fs::create_dir_all(&target).map_err(EggError::CantOpenDestFile)?;
        }
        return Ok(());
    }

    if entry.uncompressed_size == 0 && entry.blocks.is_empty() {
        if !pipe_mode {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
            }
            fs::File::create(&target).map_err(EggError::CantOpenDestFile)?;
        }
        return Ok(());
    }

    let mut crypto = setup_decryptor(entry, password)?;

    // Verify the AE-2 authentication footer before creating any output, so a
    // tampered encrypted file fails without leaving a file on disk.
    if let Some(fc) = &crypto
        && let Some(auth) = &fc.auth
    {
        verify_hmac(&mut archive.reader, entry, auth)?;
    }

    let mut writer: Box<dyn Write> = if pipe_mode {
        Box::new(io::stdout())
    } else {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
        }
        Box::new(fs::File::create(&target).map_err(EggError::CantOpenDestFile)?)
    };

    let result = (|| {
        for block in &entry.blocks {
            archive.reader.seek(SeekFrom::Start(block.data_pos))?;
            let mut bounded = (&mut archive.reader).take(block.compressed_size as u64);

            let crypto_ref = crypto
                .as_mut()
                .map(|c| &mut *c.decryptor as &mut dyn Decryptor);
            let crc = decompress_block(&mut bounded, &mut writer, block, crypto_ref)?;

            if crc != block.crc32 {
                return Err(EggError::InvalidFileCrc {
                    expected: block.crc32,
                    got: crc,
                });
            }
        }
        Ok(())
    })();

    drop(writer);

    if let Err(e) = result {
        // Don't leave a partial / unverified file on disk.
        if !pipe_mode {
            let _ = fs::remove_file(&target);
        }
        return Err(e);
    }

    if !pipe_mode && let Some(ft) = entry.file_time {
        set_file_time(&target, ft);
    }

    Ok(())
}

pub fn extract_all<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
) -> EggResult<()> {
    let entries: Vec<EggFileEntry> = archive.entries.clone();
    if archive.is_solid {
        extract_all_solid(archive, &entries, dest_dir, password, pipe_mode, None)
    } else {
        for entry in &entries {
            extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
        }
        Ok(())
    }
}

pub fn extract_files<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    files: &[String],
) -> EggResult<()> {
    let entries: Vec<EggFileEntry> = archive.entries.clone();
    if archive.is_solid {
        extract_all_solid(
            archive,
            &entries,
            dest_dir,
            password,
            pipe_mode,
            Some(files),
        )
    } else {
        for entry in &entries {
            if should_extract(entry, Some(files)) {
                extract_entry(archive, entry, dest_dir, password, pipe_mode)?;
            }
        }
        Ok(())
    }
}

/// Solid archive extraction. The blocks form one continuous compressed stream
/// (decompressor state carries across block boundaries), so it is decompressed
/// as a unit — but instead of buffering the whole output in RAM, it is streamed
/// through `SolidSink`, which routes each block's bytes to its file and verifies
/// per-block CRC as bytes arrive. Peak memory stays at the codec working set.
fn extract_all_solid<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    entries: &[EggFileEntry],
    dest_dir: &Path,
    password: Option<&str>,
    pipe_mode: bool,
    filter: Option<&[String]>,
) -> EggResult<()> {
    struct SolidBlock {
        file_idx: usize,
        uncompressed_size: u32,
        compressed_size: u32,
        crc32: u32,
        data_pos: u64,
    }

    let mut solid_blocks: Vec<SolidBlock> = Vec::new();

    for (fi, entry) in entries.iter().enumerate() {
        if entry.is_directory() {
            // Only materialize directory entries that pass the filter; file
            // parents are created on demand by the sink.
            if !pipe_mode && should_extract(entry, filter) {
                let dir_path = safe_join(dest_dir, &entry.file_name)?;
                fs::create_dir_all(&dir_path).map_err(EggError::CantOpenDestFile)?;
            }
            continue;
        }

        // Validate the destination path up front so a path-traversal entry fails
        // cleanly before any decompression happens.
        let _ = safe_join(dest_dir, &entry.file_name)?;

        for block in &entry.blocks {
            solid_blocks.push(SolidBlock {
                file_idx: fi,
                uncompressed_size: block.uncompressed_size,
                compressed_size: block.compressed_size,
                crc32: block.crc32,
                data_pos: block.data_pos,
            });
        }
    }

    if !solid_blocks.is_empty() {
        // Read and decrypt every block into one compressed buffer (bounded by the
        // archive's own size), maintaining per-file decryptor state and verifying
        // each encrypted file's AE-2 authentication footer.
        let mut all_compressed = Vec::new();
        let mut current_file_idx = usize::MAX;
        let mut crypto: Option<FileCrypto> = None;

        for sb in &solid_blocks {
            if sb.file_idx != current_file_idx {
                current_file_idx = sb.file_idx;
                crypto = setup_decryptor(&entries[sb.file_idx], password)?;
                if let Some(fc) = &crypto
                    && let Some(auth) = &fc.auth
                {
                    verify_hmac(&mut archive.reader, &entries[sb.file_idx], auth)?;
                }
            }

            archive.reader.seek(SeekFrom::Start(sb.data_pos))?;
            let want = sb.compressed_size as u64;
            let mut buf = Vec::new();
            if (&mut archive.reader).take(want).read_to_end(&mut buf)? as u64 != want {
                return Err(EggError::CorruptedFile);
            }
            if let Some(fc) = crypto.as_mut() {
                fc.decryptor.decrypt(&mut buf);
            }
            all_compressed.extend_from_slice(&buf);
        }

        let method = entries
            .iter()
            .flat_map(|e| e.blocks.iter())
            .next()
            .map(|b| b.compression_method)
            .unwrap_or(CompressionMethod::Store);

        let total_uncompressed: u64 = solid_blocks
            .iter()
            .map(|b| b.uncompressed_size as u64)
            .sum();

        let blocks: Vec<(usize, u32, u32)> = solid_blocks
            .iter()
            .map(|b| (b.file_idx, b.uncompressed_size, b.crc32))
            .collect();
        let mut sink = SolidSink::new(&blocks, entries, dest_dir, filter, pipe_mode);

        let mut cursor = Cursor::new(&all_compressed);
        let len = all_compressed.len() as u64;
        match method {
            CompressionMethod::Store => {
                io::copy(&mut cursor, &mut sink).map_err(EggError::Io)?;
            }
            CompressionMethod::Deflate => {
                decompress::deflate::extract_deflate(&mut cursor, &mut sink, len, None)?;
            }
            CompressionMethod::Bzip2 => {
                decompress::bzip2::extract_bzip2(&mut cursor, &mut sink, len, None)?;
            }
            CompressionMethod::Lzma => {
                decompress::lzma::extract_lzma(
                    &mut cursor,
                    &mut sink,
                    len,
                    total_uncompressed,
                    None,
                )?;
            }
            CompressionMethod::Azo => {
                decompress::azo::extract_azo(
                    &mut cursor,
                    &mut sink,
                    len,
                    total_uncompressed,
                    None,
                )?;
            }
            CompressionMethod::Unknown(n) => return Err(EggError::UnknownCompressionMethod(n)),
        }
        sink.finish()?;
    }

    // Create empty files for zero-block regular entries (never represented as
    // solid blocks), and apply modification times.
    if !pipe_mode {
        for entry in entries {
            if entry.is_directory() || !should_extract(entry, filter) {
                continue;
            }
            let path = safe_join(dest_dir, &entry.file_name)?;
            if entry.blocks.is_empty() {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(EggError::CantOpenDestFile)?;
                }
                fs::File::create(&path).map_err(EggError::CantOpenDestFile)?;
            }
            if let Some(ft) = entry.file_time {
                set_file_time(&path, ft);
            }
        }
    }

    Ok(())
}

/// Streaming sink for solid decompression: splits one decompressed stream back
/// into individual files by block boundary, verifying each block's CRC32 as it
/// completes and rejecting any output beyond the declared total (bomb guard).
struct SolidSink<'a> {
    blocks: &'a [(usize, u32, u32)], // (file_idx, uncompressed_size, crc32)
    entries: &'a [EggFileEntry],
    dest_dir: &'a Path,
    filter: Option<&'a [String]>,
    pipe_mode: bool,
    blk_idx: usize,
    blk_written: u32,
    hasher: crc32fast::Hasher,
    cur_file_idx: usize,
    writer: Option<Box<dyn Write>>,
}

impl<'a> SolidSink<'a> {
    fn new(
        blocks: &'a [(usize, u32, u32)],
        entries: &'a [EggFileEntry],
        dest_dir: &'a Path,
        filter: Option<&'a [String]>,
        pipe_mode: bool,
    ) -> Self {
        SolidSink {
            blocks,
            entries,
            dest_dir,
            filter,
            pipe_mode,
            blk_idx: 0,
            blk_written: 0,
            hasher: crc32fast::Hasher::new(),
            cur_file_idx: usize::MAX,
            writer: None,
        }
    }

    fn open_file(&mut self, file_idx: usize) -> io::Result<()> {
        self.writer = None; // flush/close the previous file first
        self.cur_file_idx = file_idx;
        let entry = &self.entries[file_idx];
        if should_extract(entry, self.filter) {
            self.writer = if self.pipe_mode {
                Some(Box::new(io::stdout()))
            } else {
                let path = safe_join(self.dest_dir, &entry.file_name)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                Some(Box::new(fs::File::create(&path)?))
            };
        }
        Ok(())
    }

    /// Ensure the whole declared stream was produced (no truncation). Any
    /// trailing zero-length blocks produce their (empty) files here, since no
    /// bytes flow through `write` to complete them.
    fn finish(mut self) -> EggResult<()> {
        while let Some(&(file_idx, size, crc32)) = self.blocks.get(self.blk_idx) {
            if size != 0 || self.blk_written != 0 {
                break;
            }
            self.open_file(file_idx).map_err(EggError::Io)?;
            if crc32 != crc32fast::hash(&[]) {
                return Err(EggError::InvalidFileCrc {
                    expected: crc32,
                    got: crc32fast::hash(&[]),
                });
            }
            self.blk_idx += 1;
        }
        if self.blk_idx != self.blocks.len() || self.blk_written != 0 {
            return Err(EggError::CorruptedFile);
        }
        Ok(())
    }
}

impl Write for SolidSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let total = buf.len();
        let mut rest = buf;
        while !rest.is_empty() {
            let Some(&(file_idx, size, crc32)) = self.blocks.get(self.blk_idx) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "solid output exceeds declared uncompressed size",
                ));
            };
            if file_idx != self.cur_file_idx {
                self.open_file(file_idx)?;
            }
            let need = (size - self.blk_written) as usize;
            let take = need.min(rest.len());
            let chunk = &rest[..take];
            self.hasher.update(chunk);
            if let Some(w) = self.writer.as_mut() {
                w.write_all(chunk)?;
            }
            self.blk_written += take as u32;
            rest = &rest[take..];
            if self.blk_written == size {
                let crc = std::mem::replace(&mut self.hasher, crc32fast::Hasher::new()).finalize();
                if crc != crc32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "solid block CRC mismatch",
                    ));
                }
                self.blk_idx += 1;
                self.blk_written = 0;
            }
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.writer.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

fn should_extract(entry: &EggFileEntry, filter: Option<&[String]>) -> bool {
    match filter {
        None => true,
        Some(files) => files.iter().any(|f| matches_filter(&entry.file_name, f)),
    }
}

/// A filter matches an entry by exact name or as a parent directory, rather
/// than by substring (which would also pull in unintended files).
fn matches_filter(name: &str, pat: &str) -> bool {
    let pat = pat.trim_end_matches('/');
    name == pat
        || name
            .strip_prefix(pat)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn decompress_block<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    block: &EggBlock,
    crypto: Option<&mut dyn Decryptor>,
) -> EggResult<u32> {
    // Cap output at the block's declared uncompressed size to stop bombs.
    let cs = block.compressed_size as u64;
    let mut w = decompress::LimitWriter::new(writer, block.uncompressed_size as u64);
    match block.compression_method {
        CompressionMethod::Store => decompress::store::extract_store(reader, &mut w, cs, crypto),
        CompressionMethod::Deflate => {
            decompress::deflate::extract_deflate(reader, &mut w, cs, crypto)
        }
        CompressionMethod::Bzip2 => decompress::bzip2::extract_bzip2(reader, &mut w, cs, crypto),
        CompressionMethod::Lzma => decompress::lzma::extract_lzma(
            reader,
            &mut w,
            cs,
            block.uncompressed_size as u64,
            crypto,
        ),
        CompressionMethod::Azo => {
            decompress::azo::extract_azo(reader, &mut w, cs, block.uncompressed_size as u64, crypto)
        }
        CompressionMethod::Unknown(n) => Err(EggError::UnknownCompressionMethod(n)),
    }
}

/// Convert Windows FILETIME to Unix timestamp and set file mtime.
fn set_file_time(path: &Path, filetime_val: u64) {
    const EPOCH_DIFF: u64 = 11644473600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if filetime_val < EPOCH_DIFF * TICKS_PER_SEC {
        return;
    }

    let unix_secs = (filetime_val / TICKS_PER_SEC).saturating_sub(EPOCH_DIFF);
    let nanos = ((filetime_val % TICKS_PER_SEC) * 100) as u32;
    let ft = filetime::FileTime::from_unix_time(unix_secs as i64, nanos);
    let _ = filetime::set_file_mtime(path, ft);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_keeps_normal_paths() {
        let dest = Path::new("/out");
        assert_eq!(
            safe_join(dest, "a/b/c.txt").unwrap(),
            Path::new("/out/a/b/c.txt")
        );
        // CurDir components are ignored.
        assert_eq!(safe_join(dest, "./a/./b").unwrap(), Path::new("/out/a/b"));
    }

    #[test]
    fn safe_join_rejects_traversal() {
        let dest = Path::new("/out");
        assert!(matches!(
            safe_join(dest, "../etc/passwd"),
            Err(EggError::PathTraversal(_))
        ));
        assert!(matches!(
            safe_join(dest, "a/../../etc/passwd"),
            Err(EggError::PathTraversal(_))
        ));
        // A bare ".." that the old substring check missed.
        assert!(matches!(
            safe_join(dest, ".."),
            Err(EggError::PathTraversal(_))
        ));
        assert!(matches!(
            safe_join(dest, "a/.."),
            Err(EggError::PathTraversal(_))
        ));
    }

    #[test]
    fn safe_join_rejects_absolute() {
        let dest = Path::new("/out");
        assert!(matches!(
            safe_join(dest, "/etc/passwd"),
            Err(EggError::PathTraversal(_))
        ));
    }

    #[test]
    fn filter_matches_exact_and_directory_only() {
        assert!(matches_filter("dir/file.txt", "dir/file.txt")); // exact
        assert!(matches_filter("dir/file.txt", "dir")); // parent dir
        assert!(matches_filter("dir/file.txt", "dir/")); // trailing slash
        assert!(!matches_filter("mydir/file.txt", "dir")); // not a substring match
        assert!(!matches_filter("dir/file.txt.bak", "dir/file.txt")); // not a prefix match
    }

    #[test]
    fn limit_writer_caps_output() {
        use std::io::Write;
        let mut sink = Vec::new();
        let mut w = decompress::LimitWriter::new(&mut sink, 4);
        assert!(w.write_all(b"abcd").is_ok());
        let mut sink2 = Vec::new();
        let mut w2 = decompress::LimitWriter::new(&mut sink2, 4);
        // Writing more than the declared size fails instead of growing unbounded.
        assert!(w2.write_all(b"abcde").is_err());
    }
}
