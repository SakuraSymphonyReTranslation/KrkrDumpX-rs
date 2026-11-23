use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "krkrdumpx-rs",
    version,
    about = "Static Kirikiri XP3 / Cxdec Hxv4 key extractor, analyzer, auto-unhasher, and extractor",
    long_about = "Extracts Kirikiri XP3 archives encrypted with Cxdec Hxv4 statically:\n\
                  1) Locate the game .exe\n\
                  2) Recover keys from the .exe (bres salt, STARTUP.TJS, BOOTSTRAP DLL, FilterManager)\n\
                  3) Parse XP3/Hxv4 tables, verify Adler32, classify headers, and auto-unhash names\n\
                  4) Write decrypted files with recovered paths and extensions."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Locate .exe, recover keys, analyze, extract, and auto-unhash all archives
    Run(RunArgs),

    /// Recover bres salt, bootstrap.dll, drip_program.json, and key binaries from .exe
    Keys(KeysArgs),

    /// Inspect XP3/Hxv4 headers, verify Adler32 checksums, and classify file types
    Analyze(AnalyzeArgs),

    /// Extract XP3 archive(s) with static key recovery and automatic unhashing
    Extract(ExtractArgs),

    /// Auto-unhash and rename files inside an already-extracted Hxv4 directory
    Unhash(UnhashArgs),

    /// Compute Hxv4 pathHash (SipHash-2-4) and fileHash (BLAKE2s-256)
    Hash(HashArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RecoveryOverrides {
    /// Explicit path to game .exe (auto-detected if omitted)
    #[arg(long)]
    pub exe: Option<PathBuf>,

    /// Reuse an existing drip_program.json instead of deriving from game .exe
    #[arg(long)]
    pub drip_program: Option<PathBuf>,

    /// Read the 8192-byte bres salt from this file instead of locating it in .exe
    #[arg(long)]
    pub salt_file: Option<PathBuf>,

    /// Read the bres salt from this PE RVA in .exe (decimal or 0x hex)
    #[arg(long)]
    pub salt_rva: Option<String>,

    /// Read the bres salt from this file offset in .exe (decimal or 0x hex)
    #[arg(long)]
    pub salt_file_offset: Option<String>,

    /// Override BOOTSTRAP DLL config table RVA (default: auto / 0x80E38)
    #[arg(long)]
    pub table_rva: Option<String>,

    /// Override STARTUP.TJS PE resource ref (default: 10/STARTUP.TJS)
    #[arg(long, default_value = "10/STARTUP.TJS")]
    pub startup_resource: String,

    /// Override BOOTSTRAP PE resource ref (default: 10/BOOTSTRAP)
    #[arg(long, default_value = "10/BOOTSTRAP")]
    pub bootstrap_resource: String,

    /// Override TEXT bres root resource ref (default: TEXT/127)
    #[arg(long, default_value = "TEXT/127")]
    pub text_resource: String,

    /// Override optional PLUGIN PE resource ref (default: 10/PLUGIN)
    #[arg(long, default_value = "10/PLUGIN")]
    pub plugin_resource: String,

    /// Bytes to skip before zlib-decompressing BOOTSTRAP payload (default: 8, auto-probed on failure)
    #[arg(long, default_value_t = 8)]
    pub bootstrap_zlib_offset: usize,

    /// Override System.bootStrap prefix string
    #[arg(long)]
    pub bootstrap_prefix: Option<String>,

    /// Override 8-byte archive seed (16 hex chars)
    #[arg(long)]
    pub archive_seed_hex: Option<String>,

    /// Force Hxv4 open_flag (0 or 1) instead of using descriptor.flags & 1
    #[arg(long)]
    pub force_open_flag: Option<u16>,

    /// Print detailed stage-by-stage diagnostic output
    #[arg(long, short = 'v')]
    pub debug: bool,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Game directory, game .exe, or .xp3 file (defaults to current directory)
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Output directory for extracted files (default: <target_dir>/krkrdumpx_out)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Specific XP3 archive(s) to extract (defaults to all .xp3 files in game directory)
    #[arg(long)]
    pub xp3: Vec<PathBuf>,

    /// Directory to store recovered keys and intermediates (default: <output>/_keys)
    #[arg(long)]
    pub keys_dir: Option<PathBuf>,

    /// Disable automatic no-.lst filename/directory unhashing
    #[arg(long)]
    pub no_unhash: bool,

    /// Automatically descramble Kirikiri scrambled UTF-16LE text files (FE FE xx FF FE)
    #[arg(long)]
    pub descramble: bool,

    /// Extra wordlist or HxNames.lst to merge with auto-unhashing
    #[arg(short = 'n', long)]
    pub names: Option<PathBuf>,

    /// Export all auto-discovered hash:name mappings to an HxNames.lst file
    #[arg(long)]
    pub export_lst: Option<PathBuf>,

    /// Also save HxCryptTool-compatible key binaries (key.bin, nonce.bin, CxdecTable.bin, etc.)
    #[arg(long)]
    pub dump_keys: bool,

    /// Include XP3 entry #0 warning placeholder files
    #[arg(long)]
    pub include_warning: bool,

    /// Extract directly into <output> without per-archive subdirectories
    #[arg(long)]
    pub flat: bool,

    /// Use keyed SipHash/BLAKE2s hashing with derived hash_key (for games where key_len != 0)
    #[arg(long)]
    pub keyed_hash: bool,

    #[command(flatten)]
    pub recovery: RecoveryOverrides,
}

#[derive(Args, Debug)]
pub struct KeysArgs {
    /// Game directory or game .exe (defaults to current directory)
    #[arg(default_value = ".")]
    pub target: PathBuf,

    /// Output work directory for salt, STARTUP.TJS.dec, bootstrap.dll, drip_program.json & key bins
    #[arg(short = 'o', long, default_value = "krkrdumpx_keys")]
    pub work_dir: PathBuf,

    /// Explicit output path for drip_program.json (default: <work_dir>/drip_program.json)
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Stop after decrypting resources and unpacking bootstrap.dll without deriving FilterManager
    #[arg(long)]
    pub skip_derive: bool,

    #[command(flatten)]
    pub recovery: RecoveryOverrides,
}

#[derive(Args, Debug)]
pub struct AnalyzeArgs {
    /// One or more .xp3 files, a game directory, or a game .exe
    #[arg(required = true)]
    pub targets: Vec<PathBuf>,

    /// Verify decrypted entries against XP3 Adler32 checksums and classify file headers
    #[arg(long)]
    pub verify: bool,

    /// Limit verification/classification to at most N entries per archive
    #[arg(long)]
    pub max_entries: Option<usize>,

    /// Save parsed Hxv4 records to a JSON file
    #[arg(long)]
    pub hxv4_json: Option<PathBuf>,

    /// Save derived 48-byte filter states to a JSON file
    #[arg(long)]
    pub states_json: Option<PathBuf>,

    /// Include warning entry #0
    #[arg(long)]
    pub include_warning: bool,

    #[command(flatten)]
    pub recovery: RecoveryOverrides,
}

#[derive(Args, Debug)]
pub struct ExtractArgs {
    /// One or more .xp3 files, a game directory, or a game .exe
    #[arg(required = true)]
    pub targets: Vec<PathBuf>,

    /// Output directory for extracted files
    #[arg(short = 'o', long)]
    pub output: PathBuf,

    /// Disable automatic no-.lst filename/directory unhashing
    #[arg(long)]
    pub no_unhash: bool,

    /// Automatically descramble Kirikiri scrambled UTF-16LE text files (FE FE xx FF FE)
    #[arg(long)]
    pub descramble: bool,

    /// Extra wordlist or HxNames.lst to merge with auto-unhashing
    #[arg(short = 'n', long)]
    pub names: Option<PathBuf>,

    /// Export all auto-discovered hash:name mappings to an HxNames.lst file
    #[arg(long)]
    pub export_lst: Option<PathBuf>,

    /// Also save derived keys (drip_program.json, key.bin, CxdecTable.bin, etc.) into <output>/_keys
    #[arg(long)]
    pub dump_keys: bool,

    /// Include XP3 entry #0 warning placeholder files
    #[arg(long)]
    pub include_warning: bool,

    /// Extract directly into <output> without per-archive subdirectories
    #[arg(long)]
    pub flat: bool,

    /// Use keyed SipHash/BLAKE2s hashing with derived hash_key
    #[arg(long)]
    pub keyed_hash: bool,

    #[command(flatten)]
    pub recovery: RecoveryOverrides,
}

#[derive(Args, Debug)]
pub struct UnhashArgs {
    /// Directory containing extracted Hxv4 hashed files/directories
    pub dir: PathBuf,

    /// CompoundStorageMedia media name suffix (default: xp3hnp)
    #[arg(long, default_value = "xp3hnp")]
    pub media_name: String,

    /// Optional 32-byte hash_key hex (only needed if --keyed is set)
    #[arg(long)]
    pub hash_key: Option<String>,

    /// Use keyed SipHash/BLAKE2s hashing
    #[arg(long)]
    pub keyed: bool,

    /// Optional extra HxNames.lst or wordlist to seed additional names
    #[arg(short = 'n', long)]
    pub names: Option<PathBuf>,

    /// Export resolved mappings to an HxNames.lst file
    #[arg(long)]
    pub export_lst: Option<PathBuf>,

    /// Show what would be renamed without modifying files on disk
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug)]
pub struct HashArgs {
    /// Filename(s) to compute Hxv4 fileHash (BLAKE2s-256) for
    #[arg(long = "file", short = 'f')]
    pub files: Vec<String>,

    /// Directory path(s) to compute Hxv4 pathHash (SipHash-2-4) for
    #[arg(long = "path", short = 'p')]
    pub paths: Vec<String>,

    /// CompoundStorageMedia media name suffix (default: xp3hnp)
    #[arg(long, default_value = "xp3hnp")]
    pub media_name: String,

    /// Optional 32-byte hash_key hex (only used if --keyed is set)
    #[arg(long)]
    pub hash_key: Option<String>,

    /// Use keyed SipHash/BLAKE2s hashing
    #[arg(long)]
    pub keyed: bool,
}
