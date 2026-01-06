//! Constant-time operations for cryptographic security
//!
//! This module provides constant-time implementations of common operations
//! that are vulnerable to timing attacks when implemented with standard Rust
//! operations. These operations ensure that execution time does not depend on
//! secret data values.
//!
//! # Security Warning
//! These operations are designed for cryptographic purposes only. They are
//! slower than standard operations but provide protection against timing attacks.
//! Do not use them for non-cryptographic code paths.

use std::cmp::Ordering;
use subtle::ConstantTimeEq;

/// Constant-time comparison of two byte arrays using subtle crate
/// 
/// Returns `true` if the arrays are equal, `false` otherwise.
/// This function runs in constant time regardless of the input values.
/// 
/// # Security Warning
/// Do NOT use this for non-cryptographic purposes. It's slower than
/// regular comparison but resistant to timing attacks.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    // Use subtle crate's constant-time comparison
    a.ct_eq(b).into()
}

/// Constant-time comparison of two fixed-size arrays
/// 
/// This is more efficient than slice comparison for fixed-size arrays.
pub fn ct_eq_fixed<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).into()
}

/// Constant-time selection between two values
/// 
/// Returns `a` if `choice` is `true`, `b` if `choice` is `false`.
/// The execution time is independent of the choice value.
/// 
/// ⚠️ LIMITATION: This function is only constant-time for types that can be
/// safely transmuted to/from bytes (like u8, u16, u32, u64, i8, i16, i32, i64).
/// For complex types, use the subtle crate's ConditionallySelectable trait.
#[allow(unsafe_code)] // Required for transmute operations in constant-time selection
pub fn ct_select<T: Copy>(choice: bool, a: T, b: T) -> T {
    // Convert boolean to mask: 0xFF if true, 0x00 if false
    let mask = -(choice as i8) as u8;
    
    match std::mem::size_of::<T>() {
        1 => {
            // Handle u8/i8
            let a_bytes = unsafe { std::mem::transmute_copy::<T, u8>(&a) };
            let b_bytes = unsafe { std::mem::transmute_copy::<T, u8>(&b) };
            let result = (a_bytes & mask) | (b_bytes & !mask);
            unsafe { std::mem::transmute_copy::<u8, T>(&result) }
        }
        2 => {
            // Handle u16/i16
            let a_bytes = unsafe { std::mem::transmute_copy::<T, u16>(&a) };
            let b_bytes = unsafe { std::mem::transmute_copy::<T, u16>(&b) };
            let mask_16 = u16::from_le_bytes([mask, mask]);
            let result = (a_bytes & mask_16) | (b_bytes & !mask_16);
            unsafe { std::mem::transmute_copy::<u16, T>(&result) }
        }
        4 => {
            // Handle u32/i32/f32
            let a_bytes = unsafe { std::mem::transmute_copy::<T, u32>(&a) };
            let b_bytes = unsafe { std::mem::transmute_copy::<T, u32>(&b) };
            let mask_32 = u32::from_le_bytes([mask, mask, mask, mask]);
            let result = (a_bytes & mask_32) | (b_bytes & !mask_32);
            unsafe { std::mem::transmute_copy::<u32, T>(&result) }
        }
        8 => {
            // Handle u64/i64/f64
            let a_bytes = unsafe { std::mem::transmute_copy::<T, u64>(&a) };
            let b_bytes = unsafe { std::mem::transmute_copy::<T, u64>(&b) };
            let mask_64 = u64::from_le_bytes([mask, mask, mask, mask, mask, mask, mask, mask]);
            let result = (a_bytes & mask_64) | (b_bytes & !mask_64);
            unsafe { std::mem::transmute_copy::<u64, T>(&result) }
        }
        _ => {
            // For other sizes, panic in debug mode to catch usage issues
            // In release mode, fall back to non-constant-time (documented limitation)
            debug_assert!(false, "ct_select: Unsupported type size - use subtle crate for complex types");
            if choice { a } else { b }
        }
    }
}

/// Constant-time byte array comparison
/// 
/// Returns `Ordering::Equal` if arrays are equal, `Ordering::Less` if
/// they're different. This function runs in constant time.
pub fn ct_compare(a: &[u8], b: &[u8]) -> Ordering {
    if a.len() != b.len() {
        return Ordering::Less;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    
    if result == 0 {
        Ordering::Equal
    } else {
        Ordering::Less
    }
}

/// Constant-time memory copy with optional masking
/// 
/// Copies `src` to `dst` in constant time. If `mask` is provided,
/// each byte is XORed with the corresponding mask byte.
/// 
/// # Panics
/// Panics if `dst` and `src` have different lengths, or if `mask`
/// is provided and has a different length than `src`.
pub fn ct_copy(dst: &mut [u8], src: &[u8], mask: Option<&[u8]>) {
    assert_eq!(dst.len(), src.len(), "Destination and source must have same length");
    
    if let Some(mask_bytes) = mask {
        assert_eq!(src.len(), mask_bytes.len(), "Mask must have same length as source");
        for i in 0..src.len() {
            dst[i] = src[i] ^ mask_bytes[i];
        }
    } else {
        for i in 0..src.len() {
            dst[i] = src[i];
        }
    }
}

/// Constant-time conditional swap
/// 
/// Swaps the contents of `a` and `b` if `condition` is `true`.
/// The swap operation runs in constant time regardless of the condition.
pub fn ct_swap(condition: bool, a: &mut [u8], b: &mut [u8]) {
    assert_eq!(a.len(), b.len(), "Arrays must have same length");
    
    // Create a mask that is either all 0s or all 1s
    let mask = -(condition as i8) as u8;
    
    for i in 0..a.len() {
        let tmp = a[i];
        a[i] ^= mask & (a[i] ^ b[i]);
        b[i] ^= mask & (tmp ^ b[i]);
    }
}

/// Constant-time check if all bytes are zero
/// 
/// Returns `true` if all bytes in the array are zero, `false` otherwise.
/// This function runs in constant time.
pub fn ct_is_zero(bytes: &[u8]) -> bool {
    let mut result = 0u8;
    for &byte in bytes {
        result |= byte;
    }
    result == 0
}

/// Constant-time conditional selection between two byte arrays
/// 
/// Returns `a` if `choice` is `true`, `b` if `choice` is `false`.
/// The execution time is independent of the choice value.
pub fn ct_select_bytes(choice: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Arrays must have same length");
    
    let mut result = vec![0u8; a.len()];
    let choice_byte = if choice { 0xFF } else { 0x00 };
    
    for i in 0..a.len() {
        // Use bitwise operations for constant-time selection
        result[i] = (choice_byte & a[i]) | (!choice_byte & b[i]);
    }
    
    result
}

/// Constant-time conditional assignment
/// 
/// Assigns `src` to `dst` if `condition` is `true`. The assignment
/// runs in constant time regardless of the condition.
pub fn ct_assign(condition: bool, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len(), "Arrays must have same length");
    
    let choice_byte = if condition { 0xFF } else { 0x00 };
    for i in 0..dst.len() {
        // Use bitwise operations for constant-time assignment
        dst[i] = (choice_byte & src[i]) | (!choice_byte & dst[i]);
    }
}

/// Constant-time XOR operation
/// 
/// Performs XOR operation in constant time. This is useful for
/// cryptographic operations where timing could leak information.
pub fn ct_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len(), "Arrays must have same length");
    
    let mut result = vec![0u8; a.len()];
    for i in 0..a.len() {
        result[i] = a[i] ^ b[i];
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ct_eq_equal_arrays() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 5];
        assert!(ct_eq(&a, &b));
    }
    
    #[test]
    fn test_ct_eq_different_arrays() {
        let a = [1, 2, 3, 4, 5];
        let b = [1, 2, 3, 4, 6];
        assert!(!ct_eq(&a, &b));
    }
    
    #[test]
    fn test_ct_eq_different_lengths() {
        let a = [1, 2, 3];
        let b = [1, 2, 3, 4];
        assert!(!ct_eq(&a, &b));
    }
    
    #[test]
    fn test_ct_eq_fixed() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];
        
        assert!(ct_eq_fixed(&a, &b));
        assert!(!ct_eq_fixed(&a, &c));
    }
    
    #[test]
    fn test_ct_is_zero_all_zeros() {
        let bytes = [0, 0, 0, 0];
        assert!(ct_is_zero(&bytes));
    }
    
    #[test]
    fn test_ct_is_zero_not_all_zeros() {
        let bytes = [0, 0, 1, 0];
        assert!(!ct_is_zero(&bytes));
    }
    
    #[test]
    fn test_ct_swap() {
        let mut a = [1, 2, 3];
        let mut b = [4, 5, 6];
        
        ct_swap(true, &mut a, &mut b);
        assert_eq!(a, [4, 5, 6]);
        assert_eq!(b, [1, 2, 3]);
        
        ct_swap(false, &mut a, &mut b);
        assert_eq!(a, [4, 5, 6]);
        assert_eq!(b, [1, 2, 3]);
    }
    
    #[test]
    fn test_ct_copy() {
        let src = [1, 2, 3, 4, 5];
        let mut dst = [0; 5];
        
        ct_copy(&mut dst, &src, None);
        assert_eq!(dst, src);
        
        let mask = [5, 4, 3, 2, 1];
        ct_copy(&mut dst, &src, Some(&mask));
        assert_eq!(dst, [4, 6, 0, 6, 4]);
    }
    
    #[test]
    fn test_ct_select_bytes() {
        let a = [1, 2, 3, 4];
        let b = [5, 6, 7, 8];
        
        let result_true = ct_select_bytes(true, &a, &b);
        let result_false = ct_select_bytes(false, &a, &b);
        
        assert_eq!(result_true, a);
        assert_eq!(result_false, b);
    }
    
    #[test]
    fn test_ct_assign() {
        let src = [1, 2, 3, 4];
        let mut dst_true = [0, 0, 0, 0];
        let mut dst_false = [0, 0, 0, 0];
        
        ct_assign(true, &mut dst_true, &src);
        ct_assign(false, &mut dst_false, &src);
        
        assert_eq!(dst_true, src);
        assert_eq!(dst_false, [0, 0, 0, 0]); // Should remain unchanged
    }
    
    #[test]
    fn test_ct_xor() {
        let a = [0x12, 0x34, 0x56, 0x78];
        let b = [0xAA, 0xBB, 0xCC, 0xDD];
        let expected = [0xB8, 0x8F, 0x9A, 0xA5];
        
        let result = ct_xor(&a, &b);
        assert_eq!(result, expected);
    }
}