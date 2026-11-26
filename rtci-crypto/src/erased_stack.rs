//! Key handling on a stack that is overwritten afterwards.
//!
//! Building a keyed object leaves copies of the key in the stack frames of the functions that
//! built it: a key schedule expanded in a local and moved to where it lives, a provider's own
//! temporaries, the state of a MAC keyed on the stack before it is boxed. A value moved out of
//! a frame is not dropped there, so no zeroize-on-drop reaches the copy left behind, and the
//! frames belong to code this crate does not control (the compiler's moves, the provider).
//! Measured with every SRTP profile (`rtci-srtp/tests/key_residue.rs`): after building a
//! context the master key with both of its AES schedules, session round keys, GHASH keys and
//! HMAC states are in the dead frames of the thread that built it.
//!
//! [`on_erased_stack`] does not chase those copies one by one. It runs the work on a stack of
//! its own and overwrites that whole stack when the work has returned: whatever any callee
//! left, in any frame, at any depth, is gone, without knowing where it was.

/// Whether [`on_erased_stack`] runs its work on a private stack on this platform (Linux,
/// Android and Apple systems on x86-64 and AArch64), or falls back to running it in place and
/// calling [`scrub_stack`](crate::scrub_stack) afterwards (everywhere else: Windows, other
/// architectures, Miri).
pub const ERASED_STACK_IS_PRIVATE: bool = cfg!(all(
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple"
    ),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
));

/// Runs `work` and erases the stack it ran on.
///
/// Where [`ERASED_STACK_IS_PRIVATE`] is true: `work` runs on a private stack of 256 KiB that
/// the calling thread keeps for this purpose (mapped on first use, with an inaccessible guard
/// below it, unmapped when the thread ends), and when `work` has returned or panicked every
/// byte of that stack is overwritten with zeros before this returns or resumes the panic.
/// Nothing `work` or anything it called left in a stack frame survives, at any depth. A call
/// made while the thread is already inside one runs on the same private stack, and the outer
/// call's overwrite covers it. What it does not cover: the value `work` returns (it is moved
/// to the caller's stack: return pointers to key material, not key material), registers, and
/// what `work` wrote elsewhere (the heap: use [`SecretVec`](crate::SecretVec) and zeroizing
/// types there).
///
/// `work` runs with 256 KiB of stack however much the calling thread has: it is for building
/// keyed objects and deriving keys, not for arbitrary code. Running off it is a fault on the
/// guard, not memory corruption.
///
/// Elsewhere, and when the private stack cannot be had (the mapping fails, or the thread is
/// being torn down): `work` runs in a frame of its own on the caller's stack and
/// [`scrub_stack`](crate::scrub_stack) overwrites the 32 KiB below the caller's frame
/// afterwards, which reaches what a release build's key handling uses and nothing deeper.
pub fn on_erased_stack<R>(work: impl FnOnce() -> R) -> R {
    imp::run(work)
}

/// The fallback: `work` in a frame of its own, then the stack below this frame overwritten.
#[inline(never)]
fn in_place<R>(work: impl FnOnce() -> R) -> R {
    #[inline(never)]
    fn own_frame<R>(work: impl FnOnce() -> R) -> R {
        work()
    }
    let value = own_frame(work);
    crate::scrub_stack();
    value
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
)))]
mod imp {
    pub(super) fn run<R>(work: impl FnOnce() -> R) -> R {
        super::in_place(work)
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android", target_vendor = "apple"),
    any(target_arch = "x86_64", target_arch = "aarch64"),
    not(miri)
))]
mod imp {
    use std::cell::{Cell, OnceCell};
    use std::ffi::c_void;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::ptr::NonNull;
    use std::sync::atomic::{Ordering, compiler_fence};

    /// The private stack. Building an SRTP context uses 42 KiB of stack in an unoptimised
    /// build and a few in an optimised one (`rtci-srtp/tests/key_residue.rs` prints it); a
    /// provider supplied by the application runs here too, hence the margin.
    pub(super) const STACK_SIZE: usize = 256 * 1024;
    /// Below the stack, inaccessible. A multiple of every page size in use (4, 16, 64 KiB),
    /// and more than one page so that a frame with a large uninitialised local cannot step
    /// over it.
    const GUARD_SIZE: usize = 64 * 1024;

    /// A mapping of `GUARD_SIZE + STACK_SIZE` bytes: the guard, then the stack.
    pub(super) struct PrivateStack {
        mapping: NonNull<u8>,
    }

    impl PrivateStack {
        fn new() -> Option<Self> {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            const FLAGS: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK;
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            const FLAGS: libc::c_int = libc::MAP_PRIVATE | libc::MAP_ANON;
            // SAFETY: a new anonymous mapping at an address the kernel picks, inaccessible at
            // first; then its upper `STACK_SIZE` bytes, which lie inside it, are made readable
            // and writable. On failure the mapping is removed again.
            unsafe {
                let mapping = libc::mmap(
                    std::ptr::null_mut(),
                    GUARD_SIZE + STACK_SIZE,
                    libc::PROT_NONE,
                    FLAGS,
                    -1,
                    0,
                );
                if mapping == libc::MAP_FAILED {
                    return None;
                }
                let stack = mapping.cast::<u8>().add(GUARD_SIZE).cast::<c_void>();
                if libc::mprotect(stack, STACK_SIZE, libc::PROT_READ | libc::PROT_WRITE) != 0 {
                    libc::munmap(mapping, GUARD_SIZE + STACK_SIZE);
                    return None;
                }
                NonNull::new(mapping.cast::<u8>()).map(|mapping| Self { mapping })
            }
        }

        /// The lowest address of the stack (just above the guard).
        pub(super) fn low(&self) -> *mut u8 {
            // SAFETY: `GUARD_SIZE` is inside the mapping.
            unsafe { self.mapping.as_ptr().add(GUARD_SIZE) }
        }

        /// One past the highest address of the stack: where a stack pointer starts. Page
        /// aligned, so aligned to 16 bytes as both ABIs require.
        fn top(&self) -> *mut u8 {
            // SAFETY: one past the end of the mapping.
            unsafe { self.low().add(STACK_SIZE) }
        }

        /// Overwrites the whole stack with zeros.
        fn erase(&self) {
            // SAFETY: the `STACK_SIZE` bytes from `low` are this mapping's, readable and
            // writable, and nothing runs on them: the work has returned to the caller's stack.
            unsafe { std::ptr::write_bytes(self.low(), 0, STACK_SIZE) };
            // The stack is used again by the next call and its memory is reachable through
            // the thread-local, so the fill is no dead store; the fence says so to a compiler
            // that inlines this into a thread's last use of it.
            std::hint::black_box(self.low());
            compiler_fence(Ordering::SeqCst);
        }
    }

    impl Drop for PrivateStack {
        fn drop(&mut self) {
            // SAFETY: the mapping is this value's, made in `new` with this size; nothing runs
            // on it (it is dropped with the thread's thread-locals, or on a failed start).
            unsafe {
                libc::munmap(
                    self.mapping.as_ptr().cast::<c_void>(),
                    GUARD_SIZE + STACK_SIZE,
                );
            }
        }
    }

    pub(super) struct State {
        /// Mapped on first use; `None` inside when the mapping failed.
        pub(super) stack: OnceCell<Option<PrivateStack>>,
        /// Whether the thread is running work on its private stack right now.
        busy: Cell<bool>,
    }

    thread_local! {
        pub(super) static STATE: State = const {
            State {
                stack: OnceCell::new(),
                busy: Cell::new(false),
            }
        };
    }

    /// What `trampoline` is handed: the work, and where its outcome goes. It lives in the
    /// caller's frame, on the caller's stack.
    struct Call<F, R> {
        work: Option<F>,
        outcome: Option<std::thread::Result<R>>,
    }

    /// Runs the work of the `Call<F, R>` at `call`. Called on the private stack.
    ///
    /// # Safety
    ///
    /// `call` points to a live `Call<F, R>` that nothing else uses during the call.
    unsafe extern "C" fn trampoline<F: FnOnce() -> R, R>(call: *mut u8) {
        // SAFETY: the caller's contract.
        let call = unsafe { &mut *call.cast::<Call<F, R>>() };
        if let Some(work) = call.work.take() {
            // A panic must not unwind through `call_on_stack`: it is caught here, on the
            // private stack, and resumed by `run` on the caller's once this stack is erased.
            call.outcome = Some(catch_unwind(AssertUnwindSafe(work)));
        }
    }

    /// Calls `function(argument)` with the stack pointer at `top`, and returns with the
    /// caller's stack pointer restored.
    ///
    /// The frame pointer register is callee-saved in both ABIs: it is pushed with the return
    /// address on the caller's stack (the usual frame record), keeps the caller's stack
    /// pointer across the call, and is restored on the way out. Nothing else is saved, because
    /// nothing else is changed: `function` follows the C ABI and preserves what it must.
    ///
    /// # Safety
    ///
    /// `top` is the 16-byte-aligned upper end of memory that is readable and writable below
    /// it for as deep as `function` goes and that nothing else uses during the call;
    /// `function` must not unwind.
    #[cfg(target_arch = "x86_64")]
    #[unsafe(naked)]
    unsafe extern "C" fn call_on_stack(
        argument: *mut u8,
        function: unsafe extern "C" fn(*mut u8),
        top: *mut u8,
    ) {
        // System V AMD64: argument in rdi, function in rsi, top in rdx. On entry rsp + 8 is
        // 16-byte aligned; `top` is, which is what a `call` needs.
        core::arch::naked_asm!(
            ".cfi_startproc",
            "push rbp",
            ".cfi_adjust_cfa_offset 8",
            ".cfi_rel_offset rbp, 0",
            "mov rbp, rsp",
            ".cfi_def_cfa_register rbp",
            "mov rsp, rdx",
            "call rsi",
            "mov rsp, rbp",
            "pop rbp",
            ".cfi_def_cfa rsp, 8",
            ".cfi_restore rbp",
            "ret",
            ".cfi_endproc",
        )
    }

    /// See the x86-64 form.
    #[cfg(target_arch = "aarch64")]
    #[unsafe(naked)]
    unsafe extern "C" fn call_on_stack(
        argument: *mut u8,
        function: unsafe extern "C" fn(*mut u8),
        top: *mut u8,
    ) {
        // AAPCS64: argument in x0, function in x1, top in x2.
        core::arch::naked_asm!(
            ".cfi_startproc",
            "stp x29, x30, [sp, #-16]!",
            ".cfi_adjust_cfa_offset 16",
            ".cfi_rel_offset x29, 0",
            ".cfi_rel_offset x30, 8",
            "mov x29, sp",
            ".cfi_def_cfa_register x29",
            "mov sp, x2",
            "blr x1",
            "mov sp, x29",
            ".cfi_def_cfa_register sp",
            "ldp x29, x30, [sp], #16",
            ".cfi_adjust_cfa_offset -16",
            ".cfi_restore x29",
            ".cfi_restore x30",
            "ret",
            ".cfi_endproc",
        )
    }

    enum Ran<R> {
        /// On the private stack, which has been erased.
        Erased(std::thread::Result<R>),
        /// The thread is already on its private stack: the work is to run where it is.
        Nested,
        /// No private stack to be had.
        Unavailable,
    }

    pub(super) fn run<F: FnOnce() -> R, R>(work: F) -> R {
        let mut call = Call {
            work: Some(work),
            outcome: None,
        };
        let ran = STATE
            .try_with(|state| {
                if state.busy.get() {
                    return Ran::Nested;
                }
                let Some(stack) = state.stack.get_or_init(PrivateStack::new) else {
                    return Ran::Unavailable;
                };
                state.busy.set(true);
                // SAFETY: `stack.top()` is the page-aligned upper end of `STACK_SIZE` readable
                // and writable bytes over a guard, used by this thread only and, `busy` says,
                // not at this moment; `call` lives in this frame for the whole call and
                // nothing else touches it; `trampoline` catches every panic.
                unsafe {
                    call_on_stack(
                        (&raw mut call).cast::<u8>(),
                        trampoline::<F, R>,
                        stack.top(),
                    );
                }
                stack.erase();
                state.busy.set(false);
                match call.outcome.take() {
                    Some(outcome) => Ran::Erased(outcome),
                    // `trampoline` always sets it; if it ever did not, the work has not run.
                    None => Ran::Unavailable,
                }
            })
            .unwrap_or(Ran::Unavailable);
        match (ran, call.work.take()) {
            (Ran::Erased(Ok(value)), _) => value,
            (Ran::Erased(Err(panic)), _) => resume_unwind(panic),
            (Ran::Nested, Some(work)) => work(),
            (Ran::Unavailable, Some(work)) => super::in_place(work),
            (Ran::Nested | Ran::Unavailable, None) => {
                unreachable!("the work was neither run nor left to run")
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The calling thread's private stack as `(lowest address, bytes that are not zero)`.
        fn private_stack() -> (usize, usize) {
            STATE.with(|state| {
                let stack = state
                    .stack
                    .get()
                    .and_then(Option::as_ref)
                    .expect("the private stack is mapped");
                // SAFETY: the stack is mapped and nothing runs on it.
                let bytes = unsafe { std::slice::from_raw_parts(stack.low(), STACK_SIZE) };
                (
                    stack.low() as usize,
                    bytes.iter().filter(|&&b| b != 0).count(),
                )
            })
        }

        /// Fills a local of `len` bytes with a mark and returns its address.
        #[inline(never)]
        fn leave_a_mark(len: usize) -> usize {
            let mut area = [0u8; 4096];
            let len = len.min(area.len());
            for byte in &mut area[..len] {
                // SAFETY: a valid, aligned, exclusive reference.
                unsafe { std::ptr::write_volatile(byte, 0xd7) };
            }
            std::hint::black_box(&mut area);
            area.as_ptr() as usize
        }

        #[test]
        fn the_work_runs_on_the_private_stack_and_nothing_it_wrote_there_is_left() {
            let here = 0u8;
            let caller = std::hint::black_box(&here) as *const u8 as usize;
            let (mark, value) = on_erased_stack_for_tests(|| (leave_a_mark(4096), 41 + 1));
            assert_eq!(42, value);
            let (low, not_zero) = private_stack();
            assert!(
                (low..low + STACK_SIZE).contains(&mark),
                "the work's frames were at {mark:#x}, outside the private stack at {low:#x}"
            );
            assert!(
                !(low..low + STACK_SIZE).contains(&caller),
                "the caller is on the private stack"
            );
            assert_eq!(
                0, not_zero,
                "bytes of the private stack that are not zero after the work"
            );
        }

        fn on_erased_stack_for_tests<R>(work: impl FnOnce() -> R) -> R {
            run(work)
        }

        #[test]
        fn a_panic_is_resumed_on_the_callers_stack_after_the_private_one_is_erased() {
            let caught = catch_unwind(|| {
                run(|| {
                    leave_a_mark(4096);
                    panic!("from the work");
                })
            });
            let message = caught.expect_err("the panic comes out");
            assert_eq!(Some(&"from the work"), message.downcast_ref::<&str>());
            assert_eq!(0, private_stack().1, "not erased after a panic");
            // And the stack is usable again.
            assert_eq!(7, run(|| 7));
        }

        #[test]
        fn a_call_from_inside_runs_on_the_same_stack_and_the_outer_one_erases_it() {
            let (outer, inner) = run(|| {
                let outer = leave_a_mark(64);
                let inner = run(|| leave_a_mark(4096));
                (outer, inner)
            });
            let (low, not_zero) = private_stack();
            assert!((low..low + STACK_SIZE).contains(&outer));
            assert!((low..low + STACK_SIZE).contains(&inner));
            assert_eq!(0, not_zero);
        }

        #[test]
        fn each_thread_has_a_private_stack_of_its_own() {
            run(|| leave_a_mark(16));
            let here = private_stack().0;
            let there = std::thread::spawn(|| {
                run(|| leave_a_mark(16));
                private_stack()
            })
            .join()
            .expect("the thread ends");
            assert_ne!(here, there.0);
            assert_eq!(0, there.1);
        }

        #[test]
        fn deep_work_fits() {
            #[inline(never)]
            fn deep(levels: usize) -> usize {
                let mut frame = [0u8; 1024];
                std::hint::black_box(&mut frame);
                if levels == 0 { 0 } else { 1 + deep(levels - 1) }
            }
            // About 200 KiB of the 256.
            assert_eq!(180, run(|| deep(180)));
            assert_eq!(0, private_stack().1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_value_of_the_work_is_returned_on_every_platform() {
        let secret = [1u8, 2, 3];
        assert_eq!(6u8, on_erased_stack(|| secret.iter().sum()));
        assert_eq!(3, on_erased_stack(move || secret.len()));
    }

    #[test]
    fn the_fallback_runs_the_work_in_place() {
        assert_eq!("in place", in_place(|| "in place"));
    }
}
