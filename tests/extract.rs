//! Regression tests that extract the real EGG archives under tests/data/.

use std::path::Path;

const EGG_DIR: &str = "tests/data";
const PASSWORD: &str = "test1234";

/// (name, length, CRC-32) of the original files the sample archives contain.
/// large_10M.txt only exists in the split archive.
const SOURCE: &[(&str, u64, u32)] = &[
    ("hello.txt", 131, 0x1b239eb9),
    ("repeated.txt", 720, 0x33ab076a),
    ("binary.bin", 1024, 0xb70b4c26),
    ("empty.txt", 0, 0x00000000),
    ("euckr_content.txt", 71, 0x3e3e0f3f),
    ("large.txt", 131364, 0xfe5598ec),
    ("subdir/inner.txt", 28, 0xda872f18),
    ("subdir/nested/deep.txt", 20, 0xaab59c3d),
    ("뷁테스트.txt", 72, 0x64205eb3),
    ("한글파일.txt", 56, 0xf223d6ec),
    ("large_10M.txt", 10485774, 0xdee4d582),
];

fn verify(dir: &Path, name: &str) {
    let (_, len, crc) = SOURCE.iter().find(|(n, ..)| *n == name).unwrap();
    let data = std::fs::read(dir.join(name)).unwrap();
    assert_eq!(data.len() as u64, *len, "{name}: wrong length");
    assert_eq!(crc32fast::hash(&data), *crc, "{name}: wrong CRC");
}

fn require(path: &str) {
    assert!(Path::new(path).is_file(), "test archive missing: {path}");
}

fn extract_and_verify(egg_path: &str, password: Option<&str>) {
    require(egg_path);

    let tmpdir = std::env::temp_dir().join(format!(
        "unegg_real_{}",
        Path::new(egg_path).file_stem().unwrap().to_str().unwrap()
    ));
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let file = std::fs::File::open(egg_path).unwrap();
    let mut archive = unegg::archive::EggArchive::open(file).unwrap();
    unegg::extract::extract_all(&mut archive, &tmpdir, password, false).unwrap();

    for (name, ..) in SOURCE.iter().filter(|(n, ..)| *n != "large_10M.txt") {
        verify(&tmpdir, name);
    }

    let _ = std::fs::remove_dir_all(&tmpdir);
}

// --- Compression methods ---

#[test]
fn test_real_store() {
    extract_and_verify(&format!("{EGG_DIR}/store.egg"), None);
}

#[test]
fn test_real_optimal() {
    // Optimal uses Bzip2 for text, Deflate for binary
    extract_and_verify(&format!("{EGG_DIR}/optimal.egg"), None);
}

#[test]
fn test_real_max() {
    // Max uses LZMA
    extract_and_verify(&format!("{EGG_DIR}/max.egg"), None);
}

#[test]
fn test_real_normal() {
    // Normal uses Deflate
    extract_and_verify(&format!("{EGG_DIR}/normal.egg"), None);
}

#[test]
fn test_real_low() {
    // Low uses Deflate
    extract_and_verify(&format!("{EGG_DIR}/low.egg"), None);
}

// --- Solid archives ---

#[test]
fn test_real_solid_low() {
    extract_and_verify(&format!("{EGG_DIR}/solid_low.egg"), None);
}

#[test]
fn test_real_solid_max() {
    extract_and_verify(&format!("{EGG_DIR}/solid_max.egg"), None);
}

// --- Encryption ---

#[test]
fn test_real_zip20() {
    extract_and_verify(&format!("{EGG_DIR}/zip20.egg"), Some(PASSWORD));
}

#[test]
fn test_real_aes128() {
    extract_and_verify(&format!("{EGG_DIR}/aes128.egg"), Some(PASSWORD));
}

#[test]
fn test_real_aes256() {
    extract_and_verify(&format!("{EGG_DIR}/aes256.egg"), Some(PASSWORD));
}

#[test]
fn test_real_lea128() {
    extract_and_verify(&format!("{EGG_DIR}/lea128.egg"), Some(PASSWORD));
}

#[test]
fn test_real_lea256() {
    extract_and_verify(&format!("{EGG_DIR}/lea256.egg"), Some(PASSWORD));
}

// --- Split archive ---

#[test]
fn test_real_split() {
    let vol1 = format!("{EGG_DIR}/split.vol1.egg");
    require(&vol1);

    let tmpdir = std::env::temp_dir().join("unegg_real_split");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();

    let mvr = unegg::volume::MultiVolumeReader::try_open(Path::new(&vol1))
        .unwrap()
        .expect("should detect split archive");
    assert!(mvr.volume_count() > 1);

    let mut archive = unegg::archive::EggArchive::open(mvr).unwrap();
    unegg::extract::extract_all(&mut archive, &tmpdir, None, false).unwrap();

    verify(&tmpdir, "large_10M.txt");

    let _ = std::fs::remove_dir_all(&tmpdir);
}
