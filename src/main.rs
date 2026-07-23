//! `unegg`: command-line EGG archive extractor.

use std::fs;
use std::io::{self, BufReader, Read, Seek};
use std::path::{Path, PathBuf};
use std::process;

use unegg::archive::EggArchive;
use unegg::extract;
use unegg::volume::MultiVolumeReader;

const USAGE: &str = "\
usage: unegg [-l] [-p] [-q] [-d DIR] [--pwd PASSWORD] <archive.egg | -> [files...]

  -l, --list      list archive contents
  -p              extract to stdout (pipe)
  -q, --quiet     suppress progress messages
  -d DIR          output directory (default: .)
  --pwd PASSWORD  decryption password
  -h, --help      show this help
  -V, --version   show version";

struct Cli {
    list: bool,
    pipe: bool,
    quiet: bool,
    dest_dir: Option<String>,
    password: Option<String>,
    archive: String,
    files: Vec<String>,
}

fn parse_args() -> Result<Cli, String> {
    let mut list = false;
    let mut pipe = false;
    let mut quiet = false;
    let mut dest_dir = None;
    let mut password = None;
    let mut positional: Vec<String> = Vec::new();
    let mut rest_positional = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if rest_positional {
            positional.push(arg);
            continue;
        }
        match arg.as_str() {
            "-l" | "--list" => list = true,
            "-p" => pipe = true,
            "-q" | "--quiet" => quiet = true,
            "-d" => dest_dir = Some(args.next().ok_or("-d requires a directory")?),
            "--pwd" => password = Some(args.next().ok_or("--pwd requires a password")?),
            "-h" | "--help" => {
                println!("{USAGE}");
                process::exit(0);
            }
            "-V" | "--version" => {
                println!("unegg {}", env!("CARGO_PKG_VERSION"));
                process::exit(0);
            }
            "--" => rest_positional = true,
            s if s.starts_with("--pwd=") => password = Some(s["--pwd=".len()..].to_string()),
            s if s.starts_with("-d") && s.len() > 2 => dest_dir = Some(s[2..].to_string()),
            s if s != "-" && s.starts_with('-') => return Err(format!("unknown option: {s}")),
            _ => positional.push(arg),
        }
    }

    if positional.is_empty() {
        return Err("no archive specified".into());
    }
    let archive = positional.remove(0);
    Ok(Cli {
        list,
        pipe,
        quiet,
        dest_dir,
        password,
        archive,
        files: positional,
    })
}

fn main() {
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("unegg: {e}\n{USAGE}");
            process::exit(2);
        }
    };

    if let Err(e) = run(&cli) {
        eprintln!("unegg: {e}");
        process::exit(1);
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    if cli.archive == "-" {
        let mut data = Vec::new();
        io::stdin().read_to_end(&mut data)?;
        let reader = io::Cursor::new(data);
        let mut archive = EggArchive::open(reader)?;
        return run_archive(&mut archive, cli);
    }

    let path = Path::new(&cli.archive);

    // Check for multi-volume archive
    if let Some(mvr) = MultiVolumeReader::try_open(path)? {
        let vol_count = mvr.volume_count();
        let mut archive = EggArchive::open(mvr)?;
        if !cli.quiet && !cli.pipe {
            eprintln!("split archive: {vol_count} volumes");
        }
        return run_archive(&mut archive, cli);
    }

    let file = fs::File::open(path).map_err(unegg::error::EggError::CantOpenFile)?;
    let reader = BufReader::new(file);
    let mut archive = EggArchive::open(reader)?;
    run_archive(&mut archive, cli)
}

fn run_archive<R: Read + Seek>(
    archive: &mut EggArchive<R>,
    cli: &Cli,
) -> Result<(), Box<dyn std::error::Error>> {
    if cli.list {
        list_archive(archive);
        return Ok(());
    }

    let dest_dir = PathBuf::from(cli.dest_dir.as_deref().unwrap_or("."));
    let pipe_mode = cli.pipe;

    // Prompt for a password (like unzip/7zip) when the archive is encrypted and
    // none was given on the command line. `prompted` owns it for the borrow.
    let prompted: String;
    let password: Option<&str> = if let Some(p) = cli.password.as_deref() {
        Some(p)
    } else if archive.is_encrypted {
        prompted = prompt_password(&archive.entries)?;
        Some(prompted.as_str())
    } else {
        None
    };

    if cli.files.is_empty() {
        extract::extract_all(archive, &dest_dir, password, pipe_mode)?;
    } else {
        extract::extract_files(archive, &dest_dir, password, pipe_mode, &cli.files)?;
    }

    if !cli.quiet && !pipe_mode {
        eprintln!("extracted {} entries", archive.entries.len());
    }
    Ok(())
}

/// Prompt on the terminal (input not echoed) for the archive password, retrying
/// up to three times and verifying each attempt before extraction begins.
fn prompt_password(
    entries: &[unegg::archive::EggFileEntry],
) -> Result<String, Box<dyn std::error::Error>> {
    for attempt in 1..=3 {
        let pw = rpassword::prompt_password("Enter password: ")?;
        if unegg::extract::verify_password(entries, &pw)? {
            return Ok(pw);
        }
        eprintln!(
            "unegg: incorrect password{}",
            if attempt < 3 { ", try again" } else { "" }
        );
    }
    Err(unegg::error::EggError::InvalidPassword.into())
}

fn list_archive<R: io::Read + io::Seek>(archive: &EggArchive<R>) {
    if archive.is_solid {
        eprintln!("[solid archive]");
    }
    if archive.split_info.is_some() {
        eprintln!("[split archive]");
    }

    for entry in &archive.entries {
        let method = if entry.blocks.is_empty() {
            "-".to_string()
        } else {
            entry.blocks[0].compression_method.name().to_string()
        };

        let enc = if entry.encrypt_info.is_some() {
            "*"
        } else {
            " "
        };

        let time_str = match entry.file_time {
            Some(ft) => format_filetime(ft),
            None => "                   ".to_string(),
        };

        let dir_marker = if entry.is_directory() { "D" } else { " " };

        println!(
            "{dir_marker}{enc} {size:>12}  {method:<7}  {time}  {name}",
            size = entry.uncompressed_size,
            method = method,
            time = time_str,
            name = entry.file_name,
        );
    }
}

fn format_filetime(filetime_val: u64) -> String {
    const EPOCH_DIFF: u64 = 11644473600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if filetime_val < EPOCH_DIFF * TICKS_PER_SEC {
        return "                   ".to_string();
    }

    let unix_secs = (filetime_val / TICKS_PER_SEC).saturating_sub(EPOCH_DIFF);

    let days = unix_secs / 86400;
    let time_of_day = unix_secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02}")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
