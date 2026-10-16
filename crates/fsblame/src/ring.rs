//! The reader of the `events` BPF ring buffer, with its data pages mapped once.
//!
//! A BPF ring buffer (`kernel/bpf/ringbuf.c`) is a consumer page, where the reader publishes
//! how far it has read, a producer page holding the kernel's position, and the data pages.
//! Each record is an 8-byte header (the payload length with the busy and discard bits, then a
//! page offset), the payload, and padding to a multiple of 8. Positions only grow; a record
//! lies at its position modulo the data size.
//!
//! The kernel maps the data pages twice in a row so that a record running past the end reads
//! as one slice, and aya's `RingBuf` maps them twice into this process too. A ring buffer
//! mapping is resident in full from the start, so that showed the 16 MiB default ring as
//! 32 MiB of RSS. [`Ring`] maps the data once and copies the record that wraps, at most one
//! per lap, into a buffer.

use std::{
    fmt, io,
    ops::Deref,
    os::fd::{AsFd as _, AsRawFd, BorrowedFd, RawFd},
    ptr::{self, NonNull},
    slice,
    sync::atomic::{self, AtomicU32, AtomicUsize, Ordering},
};

use aya::maps::{Map, MapData};

/// `BPF_RINGBUF_BUSY_BIT`: reserved by its producer, not committed yet.
const BUSY: u32 = 1 << 31;
/// `BPF_RINGBUF_DISCARD_BIT`: discarded by its producer.
const DISCARD: u32 = 1 << 30;
/// `BPF_RINGBUF_HDR_SZ`.
const HEADER: usize = 8;

/// A shared mapping, unmapped on drop.
struct Mapping {
    ptr: NonNull<u8>,
    len: usize,
}

impl Mapping {
    /// Maps `len` bytes of `fd` from `offset` with protection `prot`.
    fn new(fd: BorrowedFd<'_>, len: usize, offset: usize, prot: libc::c_int) -> io::Result<Self> {
        let offset = libc::off_t::try_from(offset).map_err(io::Error::other)?;
        // SAFETY: a new mapping at an address the kernel picks; nothing else refers to it.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                offset,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(ptr.cast()).ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(Self { ptr, len })
    }

    /// The position word at the start of the mapping.
    fn position(&self) -> &AtomicUsize {
        // SAFETY: the mapping is page-aligned, at least a page long and lives as long as the
        // reference; the kernel accesses the word atomically too.
        unsafe { self.ptr.cast::<AtomicUsize>().as_ref() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly what `new` mapped; no reference into it outlives `self`.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// The reader's side: its position and the page it publishes it in.
struct Consumer {
    page: Mapping,
    /// Where the next record starts; everything before it is read and released.
    pos: usize,
    /// A position was published since the last full fence (see [`Records::next`]).
    published: bool,
}

impl Consumer {
    /// Releases the record of `len` payload bytes at the position to the kernel.
    fn release(&mut self, len: usize) {
        self.pos += (HEADER + len).next_multiple_of(8);
        // The kernel reads it with acquire semantics before reusing the record's space.
        self.page.position().store(self.pos, Ordering::Release);
        self.published = true;
    }

    /// Orders the last published position before the loads that follow, so that either they
    /// see a record committed meanwhile, or its producer sees the position and wakes the
    /// reader (it does when the record it commits is the one at the consumer position).
    fn fence(&mut self) {
        if self.published {
            atomic::fence(Ordering::SeqCst);
            self.published = false;
        }
    }
}

/// The records of a ring buffer, through its consumer page and its producer and data pages.
struct Records {
    consumer: Consumer,
    /// The producer page, then the data pages.
    producer: Mapping,
    /// Where the data pages start in `producer`.
    data: usize,
    /// The data size (a power of two) minus one.
    mask: usize,
    /// The producer position when last read; records before it are reserved or committed.
    end: usize,
    /// The record that wraps past the end of the data pages, joined.
    joined: Vec<u8>,
}

impl Records {
    /// Records from `consumer` (the consumer page) and `producer` (the producer page, then
    /// `size` bytes of data pages), starting at the published consumer position.
    fn new(consumer: Mapping, producer: Mapping, page_size: usize, size: usize) -> Self {
        assert!(
            size.is_power_of_two() && producer.len == page_size + size,
            "a ring of {size} bytes in a mapping of {}",
            producer.len
        );
        let pos = consumer.position().load(Ordering::Acquire);
        let end = producer.position().load(Ordering::Acquire);
        Self {
            consumer: Consumer {
                page: consumer,
                pos,
                published: false,
            },
            producer,
            data: page_size,
            mask: size - 1,
            end,
            joined: Vec::new(),
        }
    }

    /// The next committed record, skipping discarded ones; `None` when the ring is empty or
    /// the next record is still being written.
    ///
    /// # Panics
    ///
    /// If a record header claims more bytes than the ring holds.
    fn next(&mut self) -> Option<Record<'_>> {
        let Self {
            consumer,
            producer,
            data,
            mask,
            end,
            joined,
        } = self;
        let size = *mask + 1;
        // SAFETY: `data` is within the mapping (checked in `new`).
        let base = unsafe { producer.ptr.as_ptr().add(*data) };
        loop {
            if consumer.pos == *end {
                consumer.fence();
                *end = producer.position().load(Ordering::Acquire);
                if consumer.pos == *end {
                    return None;
                }
            }
            let at = consumer.pos & *mask;
            // SAFETY: records are 8-aligned and the data size a multiple of 8, so the header
            // lies within the data pages; the kernel writes it atomically.
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "record headers are 8-aligned in page-aligned memory"
            )]
            let header = unsafe { &*base.add(at).cast::<AtomicU32>() };
            // Pairs with the kernel's ordered commit, so the payload is visible once the busy
            // bit is clear.
            let header = header.load(Ordering::Acquire);
            if header & BUSY != 0 {
                if !consumer.published {
                    return None;
                }
                consumer.fence();
                continue;
            }
            let len = usize::try_from(header & !(BUSY | DISCARD)).expect("usize holds u32");
            assert!(
                len <= size - HEADER,
                "ring record of {len} bytes in a {size}-byte ring"
            );
            if header & DISCARD != 0 {
                consumer.release(len);
                continue;
            }
            let start = (at + HEADER) & *mask;
            let bytes: &[u8] = if start + len <= size {
                // SAFETY: the committed payload lies within the data pages and the kernel does
                // not reuse it before the position moves past it, when the record drops.
                unsafe { slice::from_raw_parts(base.add(start), len) }
            } else {
                let head = size - start;
                joined.clear();
                // SAFETY: as above, for the payload's two parts: the end of the data pages,
                // then their start.
                unsafe {
                    joined.extend_from_slice(slice::from_raw_parts(base.add(start), head));
                    joined.extend_from_slice(slice::from_raw_parts(base, len - head));
                }
                joined
            };
            return Some(Record { bytes, consumer });
        }
    }

    /// Where the records reserved so far end.
    fn reserved(&self) -> usize {
        // Pairs with the kernel's release of the position, which follows writing the header
        // (with its length) of every record before it.
        self.producer.position().load(Ordering::Acquire)
    }

    /// The records from the reader's position up to `end`, a producer position read before:
    /// committed ones and ones still being written, not discarded ones.
    ///
    /// # Panics
    ///
    /// If a record header claims more bytes than the ring holds.
    fn unread(&self, end: usize) -> u64 {
        let size = self.mask + 1;
        // SAFETY: `data` is within the mapping (checked in `new`).
        let base = unsafe { self.producer.ptr.as_ptr().add(self.data) };
        let mut pos = self.consumer.pos;
        let mut count = 0;
        while pos < end {
            // SAFETY: as in `next`; the kernel does not reuse a record's space before the
            // consumer position moves past it.
            #[expect(
                clippy::cast_ptr_alignment,
                reason = "record headers are 8-aligned in page-aligned memory"
            )]
            let header = unsafe { &*base.add(pos & self.mask).cast::<AtomicU32>() };
            let header = header.load(Ordering::Acquire);
            let len = usize::try_from(header & !(BUSY | DISCARD)).expect("usize holds u32");
            assert!(
                len <= size - HEADER,
                "ring record of {len} bytes in a {size}-byte ring"
            );
            if header & DISCARD == 0 {
                count += 1;
            }
            pos += (HEADER + len).next_multiple_of(8);
        }
        count
    }
}

/// Where the records reserved in the ring at some instant end ([`Ring::mark`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mark(usize);

/// The `events` ring buffer, read from userspace.
pub struct Ring {
    /// The map, for its descriptor: readable while records are pending.
    map: MapData,
    records: Records,
}

impl Ring {
    /// Maps the ring buffer `map`: the consumer page read-write, the producer page and the
    /// data pages (once) read-only.
    pub fn new(map: Map) -> io::Result<Self> {
        let Map::RingBuf(map) = map else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a ring buffer map",
            ));
        };
        let size = map.info().map_err(io::Error::other)?.max_entries();
        let size = usize::try_from(size).map_err(io::Error::other)?;
        // SAFETY: sysconf has no preconditions.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| io::Error::last_os_error())?;
        let fd = map.fd().as_fd();
        let consumer = Mapping::new(fd, page_size, 0, libc::PROT_READ | libc::PROT_WRITE)?;
        let producer = Mapping::new(fd, page_size + size, page_size, libc::PROT_READ)?;
        Ok(Self {
            records: Records::new(consumer, producer, page_size, size),
            map,
        })
    }

    /// The next committed record; `None` when the ring is empty or the next record is still
    /// being written (the descriptor then polls readable until it is committed). Only one
    /// record is out at a time: its space is released when it drops.
    ///
    /// # Panics
    ///
    /// If a record header claims more bytes than the ring holds.
    #[expect(
        clippy::should_implement_trait,
        reason = "not an iterator: a record borrows the ring until it drops"
    )]
    pub fn next(&mut self) -> Option<Record<'_>> {
        self.records.next()
    }

    /// Marks where the records reserved so far end: those of the events until now.
    pub fn mark(&self) -> Mark {
        Mark(self.records.reserved())
    }

    /// Whether every record before `mark` has been read and released.
    pub fn passed(&self, mark: Mark) -> bool {
        self.records.consumer.pos >= mark.0
    }

    /// The records before `mark` not read yet, counting ones still being written and not
    /// discarded ones.
    ///
    /// # Panics
    ///
    /// If a record header claims more bytes than the ring holds.
    pub fn unread(&self, mark: Mark) -> u64 {
        self.records.unread(mark.0)
    }
}

impl AsRawFd for Ring {
    fn as_raw_fd(&self) -> RawFd {
        self.map.fd().as_fd().as_raw_fd()
    }
}

impl fmt::Debug for Ring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ring")
            .field("size", &(self.records.mask + 1))
            .field("pos", &self.records.consumer.pos)
            .field("end", &self.records.end)
            .finish_non_exhaustive()
    }
}

/// A record read from the ring; its space goes back to the kernel when it drops.
pub struct Record<'a> {
    bytes: &'a [u8],
    consumer: &'a mut Consumer,
}

impl Deref for Record<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes
    }
}

impl Drop for Record<'_> {
    fn drop(&mut self) {
        self.consumer.release(self.bytes.len());
    }
}

impl fmt::Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("pos", &self.consumer.pos)
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: usize = 4096;
    const SIZE: usize = 2 * PAGE;

    /// A ring in anonymous memory, written by the test in the kernel's place.
    struct Fake {
        records: Records,
        consumer: *const AtomicUsize,
        producer: *const AtomicUsize,
        data: *mut u8,
        /// The producer position: where the next record goes.
        pos: usize,
    }

    fn anonymous(len: usize) -> Mapping {
        // SAFETY: a new private anonymous mapping.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        Mapping {
            ptr: NonNull::new(ptr.cast()).unwrap(),
            len,
        }
    }

    impl Fake {
        /// A ring whose positions start at `start` (the reader caught up).
        fn new(start: usize) -> Self {
            let consumer = anonymous(PAGE);
            let producer = anonymous(PAGE + SIZE);
            consumer.position().store(start, Ordering::Relaxed);
            producer.position().store(start, Ordering::Relaxed);
            let (consumer_ptr, producer_ptr) = (
                consumer.ptr.as_ptr().cast_const().cast(),
                producer.ptr.as_ptr().cast_const().cast(),
            );
            // SAFETY: within the producer mapping.
            let data = unsafe { producer.ptr.as_ptr().add(PAGE) };
            Self {
                records: Records::new(consumer, producer, PAGE, SIZE),
                consumer: consumer_ptr,
                producer: producer_ptr,
                data,
                pos: start,
            }
        }

        /// Reserves a record of `payload` with header `flags` (busy, discard) and returns
        /// its position; publishes the producer position.
        fn put(&mut self, payload: &[u8], flags: u32) -> usize {
            let at = self.pos;
            let len = u32::try_from(payload.len()).unwrap();
            for (i, &b) in payload.iter().enumerate() {
                // SAFETY: within the data pages.
                unsafe { *self.data.add((at + HEADER + i) & (SIZE - 1)) = b };
            }
            self.header(at).store(len | flags, Ordering::Release);
            self.pos += (HEADER + payload.len()).next_multiple_of(8);
            // SAFETY: the producer page lives as long as `records`.
            unsafe { &*self.producer }.store(self.pos, Ordering::Release);
            at
        }

        #[expect(
            clippy::cast_ptr_alignment,
            reason = "record headers are 8-aligned in page-aligned memory"
        )]
        fn header(&self, at: usize) -> &AtomicU32 {
            // SAFETY: an 8-aligned header within the data pages.
            unsafe { &*self.data.add(at & (SIZE - 1)).cast::<AtomicU32>() }
        }

        /// The consumer position the reader published.
        fn published(&self) -> usize {
            // SAFETY: the consumer page lives as long as `records`.
            unsafe { &*self.consumer }.load(Ordering::Acquire)
        }

        fn next(&mut self) -> Option<Vec<u8>> {
            self.records.next().map(|record| record.to_vec())
        }
    }

    #[test]
    fn reads_committed_records_in_order_and_releases_each() {
        let mut ring = Fake::new(0);
        assert_eq!(ring.next(), None);
        ring.put(b"first", 0);
        ring.put(b"second record", 0);
        assert_eq!(ring.next().as_deref(), Some(&b"first"[..]));
        assert_eq!(ring.published(), 16);
        assert_eq!(ring.next().as_deref(), Some(&b"second record"[..]));
        assert_eq!(ring.published(), 16 + 24);
        assert_eq!(ring.next(), None);
    }

    #[test]
    fn a_record_is_released_only_when_dropped() {
        let mut ring = Fake::new(0);
        ring.put(b"x", 0);
        let record = ring.records.next().unwrap();
        assert_eq!(&*record, b"x");
        drop(record);
        assert_eq!(ring.published(), 16);
    }

    #[test]
    fn skips_discarded_records() {
        let mut ring = Fake::new(0);
        ring.put(b"dropped", DISCARD);
        ring.put(b"kept", 0);
        assert_eq!(ring.next().as_deref(), Some(&b"kept"[..]));
        assert_eq!(ring.published(), 16 + 16);
    }

    #[test]
    fn stops_at_a_record_being_written_until_it_is_committed() {
        let mut ring = Fake::new(0);
        let at = ring.put(b"pending", BUSY);
        ring.put(b"later", 0);
        assert_eq!(ring.next(), None);
        assert_eq!(ring.next(), None);
        ring.header(at).store(7, Ordering::Release);
        assert_eq!(ring.next().as_deref(), Some(&b"pending"[..]));
        assert_eq!(ring.next().as_deref(), Some(&b"later"[..]));
    }

    #[test]
    fn joins_a_record_that_wraps_past_the_end() {
        // The header sits 16 bytes before the end; the payload runs 8 bytes past it.
        let start = 3 * SIZE - 16;
        let mut ring = Fake::new(start);
        let payload: Vec<u8> = (0..16).collect();
        ring.put(&payload, 0);
        ring.put(b"after", 0);
        assert_eq!(ring.next(), Some(payload));
        assert_eq!(ring.published(), start + 24);
        assert_eq!(ring.next().as_deref(), Some(&b"after"[..]));
    }

    #[test]
    fn a_payload_after_a_header_at_the_end_starts_at_the_beginning() {
        let start = SIZE - HEADER;
        let mut ring = Fake::new(start);
        ring.put(b"wrapped whole", 0);
        assert_eq!(ring.next().as_deref(), Some(&b"wrapped whole"[..]));
        assert_eq!(ring.published(), start + 24);
    }

    #[test]
    fn counts_the_records_left_before_a_mark() {
        // Starts near the end, so the records wrap.
        let mut ring = Fake::new(SIZE - 24);
        ring.put(b"read", 0);
        ring.put(b"discarded", DISCARD);
        ring.put(&[7; 40], 0);
        ring.put(b"being written", BUSY);
        let mark = ring.records.reserved();
        ring.put(b"after the mark", 0);
        assert_eq!(ring.records.unread(mark), 3);
        assert_eq!(ring.next().as_deref(), Some(&b"read"[..]));
        assert_eq!(ring.records.unread(mark), 2);
        assert_eq!(ring.next().as_deref(), Some(&[7; 40][..]));
        assert_eq!(ring.records.unread(mark), 1);
        // The last one before the mark is still being written.
        assert_eq!(ring.next(), None);
        assert_eq!(ring.records.unread(mark), 1);
    }
}
