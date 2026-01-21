use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zks_otp::{KeyFile, OfflineOtp, OtpError};

#[cfg(feature = "hardware-rng")]
use zks_otp::hardware_rng::auto_detect_rng;

use chrono::DateTime;

#[derive(Parser)]
#[command(name = "zks-otp")]
#[command(about = "Offline One-Time Pad encryption tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key file
    Generate {
        /// Output key file path
        #[arg(short, long)]
        output: PathBuf,
        
        /// Key size (e.g., "1MB", "10KB", "1024")
        #[arg(short, long)]
        size: String,
        
        /// Use hardware RNG if available (Intel RDSEED)
        #[arg(long)]
        hardware: bool,
    },
    
    /// Encrypt a file using OTP
    Encrypt {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Key file to use
        #[arg(short, long)]
        key: PathBuf,
        
        /// Output encrypted file
        #[arg(short, long)]
        output: PathBuf,
        
        /// Use efficient mode (DEK) - 256-bit computational security
        #[arg(long)]
        efficient: bool,
    },
    
    /// Decrypt a file using OTP
    Decrypt {
        /// Input file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Key file to use
        #[arg(short, long)]
        key: PathBuf,
        
        /// Output decrypted file
        #[arg(short, long)]
        output: PathBuf,
        
        /// Securely delete the encrypted input file after decryption
        #[arg(long)]
        shred: bool,
        
        /// Use efficient mode (DEK) - 256-bit computational security
        #[arg(long)]
        efficient: bool,
    },
    
    /// Show key file information
    Status {
        /// Key file to inspect
        #[arg(short, long)]
        key: PathBuf,
    },
}

fn main() -> Result<(), OtpError> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Generate { output, size, hardware } => {
            generate_key_file(output, size, hardware)?;
        }
        Commands::Encrypt { input, key, output, efficient } => {
            encrypt_file(input, key, output, efficient)?;
        }
        Commands::Decrypt { input, key, output, shred, efficient } => {
            decrypt_file(input, key, output, shred, efficient)?;
        }
        Commands::Status { key } => {
            show_key_status(key)?;
        }
    }
    
    Ok(())
}

fn parse_size(size_str: &str) -> Result<u64, OtpError> {
    let size_str = size_str.to_uppercase();
    
    if let Some(kb_idx) = size_str.find("KB") {
        let num_str = &size_str[..kb_idx];
        let num: u64 = num_str.parse()
            .map_err(|_| OtpError::InvalidInput(format!("Invalid size number: {}", num_str)))?;
        return Ok(num * 1024);
    }
    
    if let Some(mb_idx) = size_str.find("MB") {
        let num_str = &size_str[..mb_idx];
        let num: u64 = num_str.parse()
            .map_err(|_| OtpError::InvalidInput(format!("Invalid size number: {}", num_str)))?;
        return Ok(num * 1024 * 1024);
    }
    
    if let Some(gb_idx) = size_str.find("GB") {
        let num_str = &size_str[..gb_idx];
        let num: u64 = num_str.parse()
            .map_err(|_| OtpError::InvalidInput(format!("Invalid size number: {}", num_str)))?;
        return Ok(num * 1024 * 1024 * 1024);
    }
    
    // Plain number (bytes)
    size_str.parse()
        .map_err(|_| OtpError::InvalidInput(format!("Invalid size format: {}", size_str)))
}

fn generate_key_file(output: PathBuf, size: String, hardware: bool) -> Result<(), OtpError> {
    let key_size = parse_size(&size)?;
    
    println!("Generating key file: {}", output.display());
    println!("Key size: {} bytes", key_size);
    
    if hardware {
        #[cfg(feature = "hardware-rng")]
        {
            println!("Using hardware RNG (Intel RDSEED)");
            let rng = auto_detect_rng()?;
            let _key_file = KeyFile::create_with_rng(&output, key_size, rng)?;
            println!("Key file generated successfully with hardware RNG");
        }
        #[cfg(not(feature = "hardware-rng"))]
        {
            println!("Hardware RNG requested but not available (compile with --features hardware-rng)");
            println!("Falling back to system RNG");
            let _key_file = KeyFile::create(&output, key_size)?;
        }
    } else {
        println!("Using system RNG");
        let _key_file = KeyFile::create(&output, key_size)?;
    }
    
    println!("Key file size: {} bytes", std::fs::metadata(&output)?.len());
    
    Ok(())
}

fn encrypt_file(input: PathBuf, key: PathBuf, output: PathBuf, efficient: bool) -> Result<(), OtpError> {
    println!("Encrypting file: {} -> {}", input.display(), output.display());
    println!("Using key file: {}", key.display());
    
    let input_size = std::fs::metadata(&input)?.len();
    
    if efficient {
        println!("Using efficient mode (DEK) - 256-bit computational security");
        let result = OfflineOtp::encrypt_efficient(&input, &mut KeyFile::open(&key)?, &output)?;
        println!("Encryption completed successfully");
        println!("Bytes encrypted: {}", result.bytes_encrypted);
        println!("Key bytes consumed: {}", result.key_bytes_consumed);
        println!("Mode: {:?}", result.mode);
    } else {
        println!("Using strict mode (information-theoretic security)");
        let result = OfflineOtp::encrypt_strict(&input, &mut KeyFile::open(&key)?, &output)?;
        println!("Encryption completed successfully");
        println!("Bytes encrypted: {}", result.bytes_encrypted);
        println!("Key bytes consumed: {}", result.key_bytes_consumed);
        println!("Mode: {:?}", result.mode);
    }
    
    Ok(())
}

fn decrypt_file(input: PathBuf, key: PathBuf, output: PathBuf, shred: bool, efficient: bool) -> Result<(), OtpError> {
    println!("Decrypting file: {} -> {}", input.display(), output.display());
    println!("Using key file: {}", key.display());
    
    let input_size = std::fs::metadata(&input)?.len();
    
    if efficient {
        println!("Using efficient mode (DEK) - 256-bit computational security");
        OfflineOtp::decrypt_efficient(&input, &mut KeyFile::open(&key)?, &output)?;
    } else {
        println!("Using strict mode (information-theoretic security)");
        OfflineOtp::decrypt_strict(&input, &mut KeyFile::open(&key)?, &output)?;
    }
    
    println!("Decryption completed successfully");
    println!("Bytes decrypted: {}", input_size);
    
    // Securely delete the encrypted input file if requested
    if shred {
        println!("Securely deleting encrypted input file...");
        secure_delete(&input)?;
        println!("Encrypted file securely deleted");
    }
    
    Ok(())
}

fn show_key_status(key: PathBuf) -> Result<(), OtpError> {
    println!("Key file: {}", key.display());
    
    let metadata = std::fs::metadata(&key)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    let file_size = metadata.len() as usize;
    println!("File size: {} bytes ({:.2} MB)", file_size, file_size as f64 / (1024.0 * 1024.0));
    
    let key_file = KeyFile::open(&key)?;
    let header = key_file.header();
    
    println!("Magic: {:02x?}", header.magic);
    println!("Version: {}", header.version);
    println!("Total bytes: {} bytes", header.total_bytes);
    println!("Used bytes: {} bytes", header.used_bytes);
    println!("Remaining bytes: {} bytes", header.total_bytes - header.used_bytes);
    println!("Usage: {:.1}%", (header.used_bytes as f64 / header.total_bytes as f64) * 100.0);
    
    // Format timestamp in human-readable format
    if let Some(dt) = DateTime::from_timestamp(header.created_at as i64, 0) {
        println!("Created at: {}", dt.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("Created at: {} (Unix timestamp)", header.created_at);
    }
    
    Ok(())
}

/// Securely delete a file by overwriting it with random data before deletion
fn secure_delete(path: &PathBuf) -> Result<(), OtpError> {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    let metadata = std::fs::metadata(path)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    let file_size = metadata.len() as usize;
    
    let mut random_data = vec![0u8; file_size];
    getrandom::fill(&mut random_data)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    file.write_all(&random_data)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    file.sync_all()
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    drop(file);
    
    std::fs::remove_file(path)
        .map_err(|e| OtpError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    
    Ok(())
}