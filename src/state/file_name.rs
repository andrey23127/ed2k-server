//! A file name stored behind one thin pointer.
//!
//! `Arc<str>` cost 16 bytes in the record (pointer + length) and 16 bytes of
//! reference counts in front of the text. Names stopped being shared when the
//! interner's dedup table was removed (2.8% hit rate), so the counts bought
//! nothing. `FileName` is a single pointer to `[len: u32][utf-8 bytes]`: 8 bytes
//! in the record and 4 in front of the text, 20 bytes less per file.
//!
//! `Option<FileName>` is still 8 bytes (the pointer is never null), which is
//! what lets `FileRecord` use "no name" as its tombstone flag.
//!
//! Cloning copies the text. Clones are made for search results and admin
//! views — bounded by the result count — never per stored file.

use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::ptr::NonNull;

const HDR: usize = std::mem::size_of::<u32>();

pub struct FileName(NonNull<u8>);

// SAFETY: FileName owns its allocation exclusively and never mutates it after
// construction, exactly like Box<str>.
unsafe impl Send for FileName {}
unsafe impl Sync for FileName {}

impl FileName {
    fn layout(len: usize) -> Layout {
        // align 4 so the length prefix is aligned; jemalloc's smallest class
        // is 8 bytes anyway.
        Layout::from_size_align(HDR + len, 4).expect("name length overflows a Layout")
    }

    pub fn new(s: &str) -> Self {
        // Names are capped long before this (limits.max_string_size and the
        // frame limit); saturating keeps a pathological length from wrapping.
        let s = if s.len() > u32::MAX as usize {
            let mut end = u32::MAX as usize;
            while !s.is_char_boundary(end) {
                end -= 1;
            }
            &s[..end]
        } else {
            s
        };
        let layout = Self::layout(s.len());
        // SAFETY: layout has non-zero size (HDR > 0). The header and the text
        // are written before the pointer escapes.
        unsafe {
            let p = alloc(layout);
            let Some(p) = NonNull::new(p) else {
                handle_alloc_error(layout)
            };
            (p.as_ptr() as *mut u32).write(s.len() as u32);
            std::ptr::copy_nonoverlapping(s.as_ptr(), p.as_ptr().add(HDR), s.len());
            FileName(p)
        }
    }

    #[inline]
    fn byte_len(&self) -> usize {
        // SAFETY: the allocation starts with an aligned u32 written in new().
        unsafe { *(self.0.as_ptr() as *const u32) as usize }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: the bytes after the header were copied from a &str in new()
        // and are never modified.
        unsafe {
            let bytes = std::slice::from_raw_parts(self.0.as_ptr().add(HDR), self.byte_len());
            std::str::from_utf8_unchecked(bytes)
        }
    }

    /// Heap bytes held, before allocator rounding.
    pub fn heap_bytes(&self) -> usize {
        HDR + self.byte_len()
    }
}

impl Drop for FileName {
    fn drop(&mut self) {
        // SAFETY: allocated in new() with this same layout.
        unsafe { dealloc(self.0.as_ptr(), Self::layout(self.byte_len())) }
    }
}

impl Clone for FileName {
    fn clone(&self) -> Self {
        FileName::new(self.as_str())
    }
}

impl std::ops::Deref for FileName {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for FileName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Debug for FileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_str(), f)
    }
}

impl std::fmt::Display for FileName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq for FileName {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for FileName {}

impl PartialEq<str> for FileName {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_text_of_any_length() {
        for s in ["", "a", "ubuntu-24.04.iso", "Ünïcödé ファイル 名前.mkv", &"x".repeat(1000)] {
            let n = FileName::new(s);
            assert_eq!(n.as_str(), s);
            assert_eq!(&*n.clone(), s);
            assert_eq!(n.heap_bytes(), 4 + s.len());
        }
    }

    #[test]
    fn is_one_pointer_and_option_costs_nothing() {
        assert_eq!(std::mem::size_of::<FileName>(), 8);
        assert_eq!(std::mem::size_of::<Option<FileName>>(), 8);
    }

    #[test]
    fn clones_are_independent() {
        let a = FileName::new("abc");
        let b = a.clone();
        drop(a);
        assert_eq!(b.as_str(), "abc");
    }
}
