//! Sample-archive test: extract every archive under tests/data/ and verify each
//! internal file against its recorded (path, length, CRC-32). The archives come
//! from real archiver builds across versions and options; many hold identical
//! content compressed differently, so agreement across them independently
//! confirms each codec and option path. Extraction already checks per-block CRC,
//! so a passing run is byte-exact, not merely error-free.

use std::path::Path;

// (archive, password, is_split, &[(path, len, crc)])
#[allow(clippy::type_complexity)] // a test-data table, not a public API type
const SAMPLES: &[(&str, Option<&str>, bool, &[(&str, u64, u32)])] = &[
    (
        "bzip2_big.egg",
        None,
        false,
        &[("huge.txt", 8100000, 0xf4710e9f)],
    ),
    (
        "deflate5.egg",
        None,
        false,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    (
        "empty_noblock.egg",
        None,
        false,
        &[("empty.txt", 0, 0x00000000)],
    ),
    (
        "enc_aes128.egg",
        Some("test1234"),
        false,
        &[("a.txt", 3150, 0x7a553a9d), ("b.bin", 512, 0x7735137b)],
    ),
    (
        "enc_aes256.egg",
        Some("test1234"),
        false,
        &[("a.txt", 3150, 0x7a553a9d), ("b.bin", 512, 0x7735137b)],
    ),
    (
        "enc_aes256_bzip2.egg",
        Some("test1234"),
        false,
        &[("text.txt", 9000, 0x1859c604)],
    ),
    (
        "enc_zip20.egg",
        Some("test1234"),
        false,
        &[("a.txt", 3150, 0x7a553a9d), ("b.bin", 512, 0x7735137b)],
    ),
    (
        "enc_zip20_bzip2.egg",
        Some("test1234"),
        false,
        &[("text.txt", 9000, 0x1859c604)],
    ),
    (
        "lzma5.egg",
        None,
        false,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    (
        "mixed_store_deflate5.egg",
        None,
        false,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    (
        "optimal5.egg",
        None,
        false,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
    (
        "split_store.vol1.egg",
        None,
        true,
        &[
            ("part0.bin", 40000, 0xcee0afee),
            ("part1.bin", 40000, 0x00bd73ad),
            ("part2.bin", 40000, 0x18b848e0),
            ("part3.bin", 40000, 0xd0333732),
        ],
    ),
    (
        "store5.egg",
        None,
        false,
        &[
            ("empty.txt", 0, 0x00000000),
            ("precompressed.gz", 95, 0x6a94d1bc),
            ("prog.sys", 2060, 0xb54ccab2),
            ("random.bin", 4096, 0x1bb92dfc),
            ("text.txt", 3150, 0x7a553a9d),
        ],
    ),
];

fn data(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

#[test]
fn samples_extract_and_verify() {
    for (arc, pwd, is_split, expected) in SAMPLES {
        let path = data(arc);
        assert!(path.is_file(), "missing sample archive: {}", path.display());

        let tmp = std::env::temp_dir().join(format!(
            "unegg_sample_{}",
            Path::new(arc).file_stem().unwrap().to_str().unwrap()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        if *is_split {
            let mvr = unegg::volume::MultiVolumeReader::try_open(&path)
                .unwrap()
                .expect("split archive should be detected");
            let mut archive = unegg::archive::EggArchive::open(mvr).unwrap();
            unegg::extract::extract_all(&mut archive, &tmp, *pwd, false)
                .unwrap_or_else(|e| panic!("{arc}: extract failed: {e}"));
        } else {
            let file = std::fs::File::open(&path).unwrap();
            let mut archive = unegg::archive::EggArchive::open(file).unwrap();
            unegg::extract::extract_all(&mut archive, &tmp, *pwd, false)
                .unwrap_or_else(|e| panic!("{arc}: extract failed: {e}"));
        }

        for (name, len, crc) in *expected {
            let got =
                std::fs::read(tmp.join(name)).unwrap_or_else(|_| panic!("{arc}: missing {name}"));
            assert_eq!(got.len() as u64, *len, "{arc}: {name} wrong length");
            assert_eq!(crc32fast::hash(&got), *crc, "{arc}: {name} wrong CRC");
        }

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
