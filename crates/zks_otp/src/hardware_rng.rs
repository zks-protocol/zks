//! Hardware RNG integration
//! 
//! This module provides hardware random number generation support,
//! including Intel RDRAND/RDSEED and USB device support.
#![allow(unsafe_code)] // Required for RDSEED instruction

use crate::{OtpError, Result};

/// Trait for hardware RNG implementations
pub trait HardwareRng: Send + Sync {
    /// Get the name of this RNG implementation
    fn name(&self) -> &'static str;
    
    /// Fill a buffer with random bytes
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()>;
    
    /// Get the entropy rate in bits per second
    fn entropy_rate_bps(&self) -> u32;
}

/// Intel RDSEED hardware RNG implementation
#[cfg(target_arch = "x86_64")]
pub struct IntelRdseed {
    rdseed_available: bool,
}

#[cfg(target_arch = "x86_64")]
impl IntelRdseed {
    /// Create a new Intel RDSEED instance, checking if RDSEED is available
    pub fn new() -> Result<Self> {
        if !Self::is_supported() {
            return Err(OtpError::HardwareRng("RDSEED instruction not supported on this CPU".to_string()));
        }
        Ok(IntelRdseed { rdseed_available: true })
    }
    
    /// Check if RDSEED instruction is supported on this CPU
    pub fn is_supported() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("rdseed")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }
    
    /// Try to get a single 64-bit random value from RDSEED
    fn get_rdseed64() -> Option<u64> {
        use core::arch::x86_64::_rdseed64_step;
        
        unsafe {
            let mut value: u64 = 0;
            // RDSEED can fail (return 0) if entropy is not available
            // We retry up to 10 times as recommended by Intel
            for _ in 0..10 {
                if _rdseed64_step(&mut value) == 1 {
                    return Some(value);
                }
            }
        }
        None
    }
}

#[cfg(target_arch = "x86_64")]
impl HardwareRng for IntelRdseed {
    fn name(&self) -> &'static str {
        "Intel RDSEED"
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        if !self.rdseed_available {
            return Err(OtpError::HardwareRng("RDSEED not available".to_string()));
        }
        
        let mut offset = 0;
        while offset < dest.len() {
            // Try to get 8 bytes of entropy
            if let Some(entropy) = Self::get_rdseed64() {
                let bytes = entropy.to_le_bytes();
                let remaining = dest.len() - offset;
                let to_copy = remaining.min(8);
                
                dest[offset..offset + to_copy].copy_from_slice(&bytes[..to_copy]);
                offset += to_copy;
            } else {
                return Err(OtpError::HardwareRng("RDSEED failed to provide entropy after retries".to_string()));
            }
        }
        Ok(())
    }

    fn entropy_rate_bps(&self) -> u32 {
        // RDSEED typically provides ~500 MB/s on modern CPUs
        4_000_000_000 // 4 Gbps
    }
}

/// Serial port RNG for USB devices (OneRNG, TrueRNG, etc.)
#[cfg(feature = "hardware-rng")]
pub struct SerialRng {
    port: std::sync::Arc<std::sync::Mutex<Box<dyn serialport::SerialPort>>>,
}

#[cfg(feature = "hardware-rng")]
impl SerialRng {
    /// Create a new serial RNG from a port name
    pub fn new(port_name: &str, baud_rate: u32) -> Result<Self> {
        let port = serialport::new(port_name, baud_rate)
            .timeout(std::time::Duration::from_secs(1))
            .open()
            .map_err(|e| OtpError::HardwareRng(format!("Failed to open serial port: {}", e)))?;
        
        Ok(SerialRng { port: std::sync::Arc::new(std::sync::Mutex::new(port)) })
    }
}

#[cfg(feature = "hardware-rng")]
impl HardwareRng for SerialRng {
    fn name(&self) -> &'static str {
        "Serial Port RNG"
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        use std::io::Read;
        
        self.port.lock().unwrap().read_exact(dest)
            .map_err(|e| OtpError::HardwareRng(format!("Serial read error: {}", e)))?;
        Ok(())
    }

    fn entropy_rate_bps(&self) -> u32 {
        // Typical serial RNG devices provide ~50-100 Kbps
        100_000
    }
}

/// System RNG fallback
pub struct SystemRng;

impl HardwareRng for SystemRng {
    fn name(&self) -> &'static str {
        "System RNG"
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        getrandom::fill(dest)
            .map_err(|e| OtpError::HardwareRng(format!("System RNG error: {}", e)))?;
        Ok(())
    }

    fn entropy_rate_bps(&self) -> u32 {
        // System RNG is typically very fast
        1_000_000_000 // 1 Gbps
    }
}

/// Auto-detect and create the best available hardware RNG
pub fn auto_detect_rng() -> Result<Box<dyn HardwareRng>> {
    #[cfg(target_arch = "x86_64")]
    {
        // Test if RDSEED is available using new constructor
        if let Ok(mut rdseed) = IntelRdseed::new() {
            // Test if RDSEED actually works by trying to fill a small buffer
            let mut test_buf = [0u8; 8];
            if rdseed.fill_bytes(&mut test_buf).is_ok() {
                return Ok(Box::new(rdseed));
            }
        }
    }
    
    // Fallback to system RNG
    Ok(Box::new(SystemRng))
}