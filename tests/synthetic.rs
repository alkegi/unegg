//! Tests against minimal EGG archives synthesized in memory.

use std::io::{Cursor, Write};

use unegg::crypto::ZipCrypto;

fn write_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}

fn write_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

const SIG_EGG_HEADER: u32 = 0x41474745;
const SIG_FILE_HEADER: u32 = 0x0A8590E3;
const SIG_FILENAME: u32 = 0x0A8591AC;
const SIG_WINDOWS_FILE_INFO: u32 = 0x2C86950B;
const SIG_ENCRYPT_INFO: u32 = 0x08D1470F;
const SIG_BLOCK_HEADER: u32 = 0x02B50C13;
const SIG_END_MARKER: u32 = 0x08E28222;

fn egg_header(buf: &mut Vec<u8>, header_id: u32) {
    write_u32(buf, SIG_EGG_HEADER);
    write_u16(buf, 0x0100);
    write_u32(buf, header_id);
    write_u32(buf, 0);
}

fn end_marker(buf: &mut Vec<u8>) {
    write_u32(buf, SIG_END_MARKER);
}

fn file_header(buf: &mut Vec<u8>, file_id: u32, uncompressed_size: u64) {
    write_u32(buf, SIG_FILE_HEADER);
    write_u32(buf, file_id);
    write_u64(buf, uncompressed_size);
}

fn filename_subheader(buf: &mut Vec<u8>, name: &[u8]) {
    write_u32(buf, SIG_FILENAME);
    write_u8(buf, 0x00);
    write_u16(buf, name.len() as u16);
    buf.extend_from_slice(name);
}

fn windows_file_info(buf: &mut Vec<u8>, filetime: u64, attr: u8) {
    write_u32(buf, SIG_WINDOWS_FILE_INFO);
    write_u8(buf, 0x00);
    write_u16(buf, 9);
    write_u64(buf, filetime);
    write_u8(buf, attr);
}

fn encrypt_info_subheader(buf: &mut Vec<u8>, method: u8, data: &[u8]) {
    write_u32(buf, SIG_ENCRYPT_INFO);
    write_u8(buf, 0x00);
    write_u16(buf, (1 + data.len()) as u16);
    write_u8(buf, method);
    buf.extend_from_slice(data);
}

fn block_header(
    buf: &mut Vec<u8>,
    method: u8,
    uncompressed_size: u32,
    compressed_data: &[u8],
    crc: u32,
) {
    write_u32(buf, SIG_BLOCK_HEADER);
    write_u8(buf, method);
    write_u8(buf, 0);
    write_u32(buf, uncompressed_size);
    write_u32(buf, compressed_data.len() as u32);
    write_u32(buf, crc);
    end_marker(buf);
    buf.extend_from_slice(compressed_data);
}

fn compute_crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

fn make_store_egg(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let crc = compute_crc32(content);
    egg_header(&mut buf, 0x12345678);
    end_marker(&mut buf);
    file_header(&mut buf, 0, content.len() as u64);
    filename_subheader(&mut buf, filename.as_bytes());
    windows_file_info(&mut buf, 132525744000000000, 0);
    end_marker(&mut buf);
    block_header(&mut buf, 0, content.len() as u32, content, crc);
    end_marker(&mut buf);
    buf
}

fn make_deflate_egg(filename: &str, content: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut buf = Vec::new();
    let crc = compute_crc32(content);
    egg_header(&mut buf, 0x12345679);
    end_marker(&mut buf);
    file_header(&mut buf, 0, content.len() as u64);
    filename_subheader(&mut buf, filename.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 1, content.len() as u32, &compressed, crc);
    end_marker(&mut buf);
    buf
}

fn make_bzip2_egg(filename: &str, content: &[u8]) -> Vec<u8> {
    use bzip2::Compression;
    use bzip2::write::BzEncoder;

    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut buf = Vec::new();
    let crc = compute_crc32(content);
    egg_header(&mut buf, 0x1234567A);
    end_marker(&mut buf);
    file_header(&mut buf, 0, content.len() as u64);
    filename_subheader(&mut buf, filename.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 2, content.len() as u32, &compressed, crc);
    end_marker(&mut buf);
    buf
}

fn make_directory_egg() -> Vec<u8> {
    let mut buf = Vec::new();
    egg_header(&mut buf, 0x1234567B);
    end_marker(&mut buf);

    file_header(&mut buf, 0, 0);
    filename_subheader(&mut buf, b"testdir/");
    windows_file_info(&mut buf, 132525744000000000, 0x80);
    end_marker(&mut buf);

    let content = b"file in directory";
    let crc = compute_crc32(content);
    file_header(&mut buf, 1, content.len() as u64);
    filename_subheader(&mut buf, b"testdir/inner.txt");
    end_marker(&mut buf);
    block_header(&mut buf, 0, content.len() as u32, content, crc);

    end_marker(&mut buf);
    buf
}

fn make_multiblock_egg() -> Vec<u8> {
    let mut buf = Vec::new();
    let part1 = b"Hello, ";
    let part2 = b"world!";
    let total_size = part1.len() + part2.len();

    egg_header(&mut buf, 0x1234567C);
    end_marker(&mut buf);
    file_header(&mut buf, 0, total_size as u64);
    filename_subheader(&mut buf, b"multiblock.txt");
    end_marker(&mut buf);
    block_header(&mut buf, 0, part1.len() as u32, part1, compute_crc32(part1));
    block_header(&mut buf, 0, part2.len() as u32, part2, compute_crc32(part2));
    end_marker(&mut buf);
    buf
}

fn zipcrypto_encrypt(zc: &mut ZipCrypto, data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    zc.encrypt(&mut out);
    out
}

fn make_zipcrypto_store_egg(filename: &str, content: &[u8], password: &str) -> Vec<u8> {
    let crc = compute_crc32(content);
    let mut zc = ZipCrypto::new(password.as_bytes());

    // Build verify header: 11 filler bytes + CRC check byte
    let mut verify_plain = [0u8; 12];
    for (i, b) in verify_plain.iter_mut().enumerate().take(11) {
        *b = (i as u8).wrapping_mul(37).wrapping_add(42);
    }
    verify_plain[11] = (crc >> 24) as u8;

    let enc_verify = zipcrypto_encrypt(&mut zc, &verify_plain);
    let enc_data = zipcrypto_encrypt(&mut zc, content);

    // Encrypt info: 12 bytes verify + 4 bytes CRC
    let mut ei_data = Vec::new();
    ei_data.extend_from_slice(&enc_verify);
    ei_data.extend_from_slice(&crc.to_le_bytes());

    let mut buf = Vec::new();
    egg_header(&mut buf, 0x1234567D);
    end_marker(&mut buf);
    file_header(&mut buf, 0, content.len() as u64);
    filename_subheader(&mut buf, filename.as_bytes());
    encrypt_info_subheader(&mut buf, 0, &ei_data);
    end_marker(&mut buf);
    block_header(&mut buf, 0, content.len() as u32, &enc_data, crc);
    end_marker(&mut buf);
    buf
}

const SIG_SPLIT_INFO: u32 = 0x24F5A262;
const SIG_SOLID_INFO: u32 = 0x24E5A060;

fn split_info(buf: &mut Vec<u8>, prev_id: u32, next_id: u32) {
    write_u32(buf, SIG_SPLIT_INFO);
    write_u8(buf, 0x00); // flags
    write_u16(buf, 8); // size = 8 bytes (prev_id + next_id)
    write_u32(buf, prev_id);
    write_u32(buf, next_id);
}

fn solid_info(buf: &mut Vec<u8>) {
    write_u32(buf, SIG_SOLID_INFO);
    write_u8(buf, 0x00); // flags
    write_u16(buf, 0); // size = 0
}

/// Build a solid archive with two Store-compressed files.
/// The compressed data is laid out as one continuous stream:
/// [file1_content][file2_content] -- each block maps to one file.
fn make_solid_store_egg(name1: &str, content1: &[u8], name2: &str, content2: &[u8]) -> Vec<u8> {
    let crc1 = compute_crc32(content1);
    let crc2 = compute_crc32(content2);

    let mut buf = Vec::new();
    egg_header(&mut buf, 0x1234567E);
    solid_info(&mut buf);
    end_marker(&mut buf);

    // File 1
    file_header(&mut buf, 0, content1.len() as u64);
    filename_subheader(&mut buf, name1.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 0, content1.len() as u32, content1, crc1);

    // File 2
    file_header(&mut buf, 1, content2.len() as u64);
    filename_subheader(&mut buf, name2.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 0, content2.len() as u32, content2, crc2);

    end_marker(&mut buf);
    buf
}

/// Build a solid archive with two Deflate-compressed files.
/// The files are compressed together as one continuous deflate stream,
/// then split across two blocks.
fn make_solid_deflate_egg(name1: &str, content1: &[u8], name2: &str, content2: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    // Compress both files as one stream
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(content1).unwrap();
    encoder.write_all(content2).unwrap();
    let all_compressed = encoder.finish().unwrap();

    let crc1 = compute_crc32(content1);
    let crc2 = compute_crc32(content2);

    // Split compressed data roughly in half for two blocks.
    // In a real solid archive, the split point is arbitrary --
    // it doesn't need to align with uncompressed boundaries.
    // We put ALL compressed data in block 1 and an empty block 2.
    // This is valid: block 2 has 0 compressed bytes but produces output
    // from the decompressor's buffered state... Actually no.
    //
    // Simpler: put all compressed data in block 1's compressed_size.
    // Block 1 covers file 1's uncompressed output.
    // Block 2 has 0 compressed bytes and covers file 2's uncompressed output.
    //
    // Wait -- that won't work because the decompressor needs the data.
    // Let's just put ALL compressed data into block 1 and make block 2 empty.
    // The decompress_solid function concatenates all block data and
    // decompresses at once, so it works.

    let mut buf = Vec::new();
    egg_header(&mut buf, 0x1234567F);
    solid_info(&mut buf);
    end_marker(&mut buf);

    // File 1 -- block carries all compressed data
    file_header(&mut buf, 0, content1.len() as u64);
    filename_subheader(&mut buf, name1.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 1, content1.len() as u32, &all_compressed, crc1);

    // File 2 -- block has 0 compressed bytes
    file_header(&mut buf, 1, content2.len() as u64);
    filename_subheader(&mut buf, name2.as_bytes());
    end_marker(&mut buf);
    block_header(&mut buf, 1, content2.len() as u32, &[], crc2);

    end_marker(&mut buf);
    buf
}

// ============ Tests ============

#[test]
fn test_store_roundtrip() {
    let content = b"Hello, EGG world!\n";
    let egg_data = make_store_egg("hello.txt", content);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].file_name, "hello.txt");
    assert_eq!(archive.entries[0].uncompressed_size, content.len() as u64);
    assert_eq!(archive.entries[0].blocks.len(), 1);
    assert_eq!(
        archive.entries[0].blocks[0].compression_method,
        unegg::archive::CompressionMethod::Store
    );

    let mut output = Vec::new();
    let entry = archive.entries[0].clone();
    let block = &entry.blocks[0];
    archive.reader.set_position(block.data_pos);
    let mut bounded = std::io::Read::take(&mut archive.reader, block.compressed_size as u64);
    let crc = unegg::decompress::store::extract_store(
        &mut bounded,
        &mut output,
        block.compressed_size as u64,
        None,
    )
    .unwrap();
    assert_eq!(crc, block.crc32);
    assert_eq!(&output, content);
}

#[test]
fn test_deflate_roundtrip() {
    let content = b"The quick brown fox jumps over the lazy dog. Repeated text for compression. The quick brown fox jumps over the lazy dog.";
    let egg_data = make_deflate_egg("deflate.txt", content);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();
    assert_eq!(archive.entries.len(), 1);

    let mut output = Vec::new();
    let entry = archive.entries[0].clone();
    let block = &entry.blocks[0];
    archive.reader.set_position(block.data_pos);
    let mut bounded = std::io::Read::take(&mut archive.reader, block.compressed_size as u64);
    let crc = unegg::decompress::deflate::extract_deflate(
        &mut bounded,
        &mut output,
        block.compressed_size as u64,
        None,
    )
    .unwrap();
    assert_eq!(crc, block.crc32);
    assert_eq!(&output, &content[..]);
}

#[test]
fn test_bzip2_roundtrip() {
    let content = b"Bzip2 compressed content for testing. AAABBBCCCDDD repeated many times. Bzip2 compressed content.";
    let egg_data = make_bzip2_egg("bzip2.txt", content);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();
    assert_eq!(archive.entries.len(), 1);

    let mut output = Vec::new();
    let entry = archive.entries[0].clone();
    let block = &entry.blocks[0];
    archive.reader.set_position(block.data_pos);
    let mut bounded = std::io::Read::take(&mut archive.reader, block.compressed_size as u64);
    let crc = unegg::decompress::bzip2::extract_bzip2(
        &mut bounded,
        &mut output,
        block.compressed_size as u64,
        None,
    )
    .unwrap();
    assert_eq!(crc, block.crc32);
    assert_eq!(&output, &content[..]);
}

#[test]
fn test_directory_entry() {
    let egg_data = make_directory_egg();
    let cursor = Cursor::new(egg_data);
    let archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert_eq!(archive.entries.len(), 2);
    assert!(archive.entries[0].is_directory());
    assert_eq!(archive.entries[0].file_name, "testdir/");
    assert!(!archive.entries[1].is_directory());
    assert_eq!(archive.entries[1].file_name, "testdir/inner.txt");
}

#[test]
fn test_multiblock() {
    let egg_data = make_multiblock_egg();
    let cursor = Cursor::new(egg_data);
    let archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert_eq!(archive.entries.len(), 1);
    assert_eq!(archive.entries[0].blocks.len(), 2);
    assert_eq!(archive.entries[0].uncompressed_size, 13);
}

#[test]
fn test_not_egg_file() {
    let data = b"not an egg file";
    let cursor = Cursor::new(data.to_vec());
    let result = unegg::archive::EggArchive::open(cursor);
    assert!(result.is_err());
}

#[test]
fn test_extract_multiblock_via_api() {
    let egg_data = make_multiblock_egg();
    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    let tmpdir = std::env::temp_dir().join("unegg_test_multiblock");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    unegg::extract::extract_all(&mut archive, &tmpdir, None, false).unwrap();

    let content = std::fs::read_to_string(tmpdir.join("multiblock.txt")).unwrap();
    assert_eq!(content, "Hello, world!");
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_zipcrypto_store_roundtrip() {
    let password = "testpass";
    let content = b"Secret encrypted content!";
    let egg_data = make_zipcrypto_store_egg("secret.txt", content, password);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert_eq!(archive.entries.len(), 1);
    assert!(archive.entries[0].encrypt_info.is_some());

    let tmpdir = std::env::temp_dir().join("unegg_test_zipcrypto");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    unegg::extract::extract_all(&mut archive, &tmpdir, Some(password), false).unwrap();

    let extracted = std::fs::read(tmpdir.join("secret.txt")).unwrap();
    assert_eq!(&extracted, content);
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_zipcrypto_wrong_password() {
    let content = b"Secret encrypted content!";
    let egg_data = make_zipcrypto_store_egg("secret.txt", content, "correctpass");

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    let tmpdir = std::env::temp_dir().join("unegg_test_wrongpwd");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let result = unegg::extract::extract_all(&mut archive, &tmpdir, Some("wrongpass"), false);
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_zipcrypto_no_password() {
    let content = b"Secret encrypted content!";
    let egg_data = make_zipcrypto_store_egg("secret.txt", content, "testpass");

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    let tmpdir = std::env::temp_dir().join("unegg_test_nopwd");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let result = unegg::extract::extract_all(&mut archive, &tmpdir, None, false);
    assert!(result.is_err());
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_solid_store() {
    let content1 = b"First file content";
    let content2 = b"Second file content";
    let egg_data = make_solid_store_egg("one.txt", content1, "two.txt", content2);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert!(archive.is_solid);
    assert_eq!(archive.entries.len(), 2);

    let tmpdir = std::env::temp_dir().join("unegg_test_solid_store");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    unegg::extract::extract_all(&mut archive, &tmpdir, None, false).unwrap();

    assert_eq!(std::fs::read(tmpdir.join("one.txt")).unwrap(), content1);
    assert_eq!(std::fs::read(tmpdir.join("two.txt")).unwrap(), content2);
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_solid_deflate() {
    let content1 = b"Solid deflate file one with repeated text repeated text repeated text";
    let content2 = b"Solid deflate file two with different content for testing";
    let egg_data = make_solid_deflate_egg("alpha.txt", content1, "beta.txt", content2);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    assert!(archive.is_solid);
    assert_eq!(archive.entries.len(), 2);

    let tmpdir = std::env::temp_dir().join("unegg_test_solid_deflate");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    unegg::extract::extract_all(&mut archive, &tmpdir, None, false).unwrap();

    assert_eq!(std::fs::read(tmpdir.join("alpha.txt")).unwrap(), content1);
    assert_eq!(std::fs::read(tmpdir.join("beta.txt")).unwrap(), content2);
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_solid_extract_filter() {
    let content1 = b"First file";
    let content2 = b"Second file";
    let egg_data = make_solid_store_egg("keep.txt", content1, "skip.txt", content2);

    let cursor = Cursor::new(egg_data);
    let mut archive = unegg::archive::EggArchive::open(cursor).unwrap();

    let tmpdir = std::env::temp_dir().join("unegg_test_solid_filter");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let files = vec!["keep.txt".to_string()];
    unegg::extract::extract_files(&mut archive, &tmpdir, None, false, &files).unwrap();

    assert_eq!(std::fs::read(tmpdir.join("keep.txt")).unwrap(), content1);
    assert!(!tmpdir.join("skip.txt").exists());
    let _ = std::fs::remove_dir_all(&tmpdir);
}

#[test]
fn test_multivolume_store() {
    // Create a 2-volume split archive:
    // Volume 1 (header_id=0xAAAA0001): contains file1, split_info points to volume 2
    // Volume 2 (header_id=0xBBBB0002): continuation, contains file2

    let content1 = b"Content of file one";
    let content2 = b"Content of file two";
    let crc1 = compute_crc32(content1);
    let crc2 = compute_crc32(content2);

    let vol1_id: u32 = 0xAAAA0001;
    let vol2_id: u32 = 0xBBBB0002;

    // Volume 1: first volume with one file
    let mut vol1 = Vec::new();
    egg_header(&mut vol1, vol1_id);
    split_info(&mut vol1, 0, vol2_id); // prev=0 (first), next=vol2
    end_marker(&mut vol1);
    file_header(&mut vol1, 0, content1.len() as u64);
    filename_subheader(&mut vol1, b"file1.txt");
    end_marker(&mut vol1);
    block_header(&mut vol1, 0, content1.len() as u32, content1, crc1);
    end_marker(&mut vol1);

    // Volume 2: continuation with one file
    let mut vol2 = Vec::new();
    egg_header(&mut vol2, vol2_id);
    split_info(&mut vol2, vol1_id, 0); // prev=vol1, next=0 (last)
    end_marker(&mut vol2);
    file_header(&mut vol2, 1, content2.len() as u64);
    filename_subheader(&mut vol2, b"file2.txt");
    end_marker(&mut vol2);
    block_header(&mut vol2, 0, content2.len() as u32, content2, crc2);
    end_marker(&mut vol2);

    // Write volumes to temp directory
    let tmpdir = std::env::temp_dir().join("unegg_test_multivolume");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let vol1_path = tmpdir.join("archive.egg");
    let vol2_path = tmpdir.join("archive.eg1");
    std::fs::write(&vol1_path, &vol1).unwrap();
    std::fs::write(&vol2_path, &vol2).unwrap();

    // Open via MultiVolumeReader
    let mvr = unegg::volume::MultiVolumeReader::try_open(&vol1_path)
        .unwrap()
        .expect("should detect split archive");
    assert_eq!(mvr.volume_count(), 2);

    let mut archive = unegg::archive::EggArchive::open(mvr).unwrap();
    assert_eq!(archive.entries.len(), 2);
    assert_eq!(archive.entries[0].file_name, "file1.txt");
    assert_eq!(archive.entries[1].file_name, "file2.txt");

    // Extract
    let out_dir = tmpdir.join("output");
    std::fs::create_dir_all(&out_dir).unwrap();
    unegg::extract::extract_all(&mut archive, &out_dir, None, false).unwrap();

    assert_eq!(std::fs::read(out_dir.join("file1.txt")).unwrap(), content1);
    assert_eq!(std::fs::read(out_dir.join("file2.txt")).unwrap(), content2);

    let _ = std::fs::remove_dir_all(&tmpdir);
}
