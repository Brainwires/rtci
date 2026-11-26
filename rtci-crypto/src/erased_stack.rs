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
/// Where [`ERASED_STACK_IS_PRIVATE`] is true: `work` runs on a private stack of 256 KiB with
/// an inaccessible guard below it (taken from a small pool of the process, mapped when none
/// is free), and when `work` has returned or panicked every byte of that stack is overwritten
/// with zeros before this returns or resumes the panic. Nothing `work` or anything it called
/// left in a stack frame survives, at any depth. A call made from inside `work` gets a stack
/// of its own. What it does not cover: the value `work` returns (it is moved to the caller's
/// stack: return pointers to key material, not key material), registers (a provider's AES
/// leaves round keys in vector registers, and whatever later saves registers to a stack, a
/// signal frame for one, puts them there), and what `work` wrote elsewhere (the heap: use
/// [`SecretVec`](crate::SecretVec) and zeroizing types there).
///
/// `work` runs with 256 KiB of stack however much the calling thread has: it is for building
/// keyed objects and deriving keys, not for arbitrary code. Running off it is a fault on the
/// guard, not memory corruption.
///
/// Elsewhere, and when no private stack can be had (the mapping fails): `work` runs in a frame of its own on the caller's stack and
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
    use std::ffi::c_void;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicPtr, Ordering, compiler_fence};

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
            // The stack is used again by a later call and its memory stays reachable through
            // the pool, so the fill is no dead store; the fence says so to a compiler that
            // inlines this next to the unmapping of a stack the pool has no room for.
            std::hint::black_box(self.low());
            compiler_fence(Ordering::SeqCst);
        }
    }

    impl Drop for PrivateStack {
        fn drop(&mut self) {
            // SAFETY: the mapping is this value's, made in `new` with this size; nothing runs
            // on it (a stack is dropped only by the call that held it, after its work).
            unsafe {
                libc::munmap(
                    self.mapping.as_ptr().cast::<c_void>(),
                    GUARD_SIZE + STACK_SIZE,
                );
            }
        }
    }

    /// The stacks not in use, each erased: a call takes one (or maps one when none is free)
    /// and puts it back when its work has returned and the stack is overwritten.
    ///
    /// A pool of the process rather than a stack per thread, on purpose: reaching a
    /// thread-local for the first time in a thread goes through the platform's lazy
    /// thread-local set-up, which on Apple systems saves the vector registers on the caller's
    /// stack, and after a provider's AES those still hold round keys. That put one AES-GCM
    /// round key of the ring provider into a dead frame of the calling thread, the very thing
    /// this module exists to prevent (run 45877045732, macOS arm64, optimised build). Taking
    /// and giving back a stack is two atomic operations and touches nothing thread-local.
    static POOL: [AtomicPtr<u8>; POOL_SLOTS] =
        [const { AtomicPtr::new(std::ptr::null_mut()) }; POOL_SLOTS];
    /// How many erased stacks are kept for the next call; a call that finds none maps one, and
    /// one that cannot put its stack back unmaps it. Each concurrent call, and each nested
    /// one, uses a stack.
    const POOL_SLOTS: usize = 8;

    fn take() -> Option<PrivateStack> {
        for slot in &POOL {
            let mapping = slot.swap(std::ptr::null_mut(), Ordering::AcqRel);
            if let Some(mapping) = NonNull::new(mapping) {
                return Some(PrivateStack { mapping });
            }
        }
        PrivateStack::new()
    }

    /// Puts an erased stack back.
    fn give(stack: PrivateStack) {
        let mapping = stack.mapping.as_ptr();
        for slot in &POOL {
            if slot
                .compare_exchange(
                    std::ptr::null_mut(),
                    mapping,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                // The pool owns the mapping now.
                std::mem::forget(stack);
                return;
            }
        }
        // No room: `stack` is dropped, which unmaps it.
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

    pub(super) fn run<F: FnOnce() -> R, R>(work: F) -> R {
        match take() {
            Some(stack) => {
                let outcome = run_on(&stack, work);
                give(stack);
                match outcome {
                    Ok(value) => value,
                    Err(panic) => resume_unwind(panic),
                }
            }
            None => super::in_place(work),
        }
    }

    /// Runs `work` on `stack` and overwrites the stack; a panic of the work is returned.
    fn run_on<F: FnOnce() -> R, R>(stack: &PrivateStack, work: F) -> std::thread::Result<R> {
        let mut call = Call {
            work: Some(work),
            outcome: None,
        };
        // SAFETY: `stack.top()` is the page-aligned upper end of `STACK_SIZE` readable and
        // writable bytes over a guard, which only this call uses (it took the stack out of
        // the pool, or mapped it); `call` lives in this frame for the whole call and nothing
        // else touches it; `trampoline` catches every panic.
        unsafe {
            call_on_stack(
                (&raw mut call).cast::<u8>(),
                trampoline::<F, R>,
                stack.top(),
            );
        }
        stack.erase();
        match call.outcome.take() {
            Some(outcome) => outcome,
            // `trampoline` always takes the work and sets the outcome.
            None => unreachable!("the work did not run"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// How many bytes of `stack` are not zero.
        fn not_zero(stack: &PrivateStack) -> usize {
            // SAFETY: the stack is mapped and nothing runs on it.
            let bytes = unsafe { std::slice::from_raw_parts(stack.low(), STACK_SIZE) };
            bytes.iter().filter(|&&b| b != 0).count()
        }

        fn holds(stack: &PrivateStack, address: usize) -> bool {
            (stack.low() as usize..stack.low() as usize + STACK_SIZE).contains(&address)
        }

        /// Fills a local with a mark and returns its address.
        #[inline(never)]
        fn leave_a_mark() -> usize {
            let mut area = [0u8; 4096];
            for byte in &mut area {
                // SAFETY: a valid, aligned, exclusive reference.
                unsafe { std::ptr::write_volatile(byte, 0xd7) };
            }
            std::hint::black_box(&mut area);
            area.as_ptr() as usize
        }

        #[test]
        fn the_work_runs_on_the_private_stack_and_nothing_it_wrote_there_is_left() {
            let stack = PrivateStack::new().expect("a stack");
            let here = 0u8;
            let caller = std::hint::black_box(&here) as *const u8 as usize;
            let (mark, value) = run_on(&stack, || (leave_a_mark(), 41 + 1)).expect("no panic");
            assert_eq!(42, value);
            assert!(
                holds(&stack, mark),
                "the work's frames were at {mark:#x}, outside the private stack"
            );
            assert!(!holds(&stack, caller), "the caller is on the private stack");
            assert_eq!(
                0,
                not_zero(&stack),
                "bytes of the private stack that are not zero after the work"
            );
        }

        #[test]
        fn a_panic_comes_back_after_the_stack_is_erased_and_the_stack_works_again() {
            let stack = PrivateStack::new().expect("a stack");
            let panic = run_on(&stack, || {
                leave_a_mark();
                panic!("from the work");
            })
            .expect_err("the panic comes back");
            assert_eq!(Some(&"from the work"), panic.downcast_ref::<&str>());
            assert_eq!(0, not_zero(&stack), "not erased after a panic");
            assert_eq!(7, run_on(&stack, || 7).expect("no panic"));
        }

        #[test]
        fn a_panic_of_the_work_is_resumed_in_the_caller() {
            let caught = catch_unwind(|| run(|| -> u8 { panic!("resumed") }));
            let panic = caught.expect_err("the panic comes out");
            assert_eq!(Some(&"resumed"), panic.downcast_ref::<&str>());
        }

        #[test]
        fn a_call_from_inside_gets_a_stack_of_its_own() {
            let (outer, inner) = run(|| {
                let outer = leave_a_mark();
                let inner = run(leave_a_mark);
                (outer, inner)
            });
            assert!(
                outer.abs_diff(inner) >= STACK_SIZE,
                "the inner work ran {} bytes from the outer one: on the same stack",
                outer.abs_diff(inner)
            );
        }

        /// Stacks are shared between threads one after the other, never at once: what a
        /// thread writes into a frame is still there after it let every other thread run.
        #[test]
        fn no_two_threads_run_on_one_stack_at_once() {
            let threads: Vec<_> = (1..=6u8)
                .map(|id| {
                    std::thread::spawn(move || {
                        for _ in 0..300 {
                            run(|| {
                                let mut frame = [0u8; 512];
                                for byte in &mut frame {
                                    // SAFETY: a valid, aligned, exclusive reference.
                                    unsafe { std::ptr::write_volatile(byte, id) };
                                }
                                std::thread::yield_now();
                                let frame = std::hint::black_box(&frame);
                                assert!(frame.iter().all(|&b| b == id), "thread {id}");
                            });
                        }
                    })
                })
                .collect();
            for thread in threads {
                thread.join().expect("no thread saw another's bytes");
            }
        }

        /// A stack that goes back to the pool is all zeros, whoever takes it next.
        #[test]
        fn a_stack_taken_from_the_pool_is_erased() {
            for _ in 0..4 {
                run(leave_a_mark);
                let stack = take().expect("a stack");
                assert_eq!(0, not_zero(&stack));
                give(stack);
            }
        }

        /// A signal that arrives while the work runs is handled on the private stack (the
        /// thread has no alternate signal stack of this module's making) and the work goes on.
        #[test]
        fn a_signal_is_delivered_while_the_work_runs_on_the_private_stack() {
            use std::sync::atomic::AtomicUsize;
            static HANDLER_FRAME: AtomicUsize = AtomicUsize::new(0);
            extern "C" fn handler(_signal: libc::c_int) {
                let here = 0u8;
                HANDLER_FRAME.store(&raw const here as usize, Ordering::SeqCst);
            }
            let stack = PrivateStack::new().expect("a stack");
            // SAFETY: a handler that only stores an address is installed for SIGUSR2, which
            // nothing else in this test binary uses, and the previous action is put back.
            let after = unsafe {
                let mut action = std::mem::zeroed::<libc::sigaction>();
                action.sa_sigaction = handler as extern "C" fn(libc::c_int) as usize;
                let mut previous = std::mem::zeroed::<libc::sigaction>();
                assert_eq!(0, libc::sigaction(libc::SIGUSR2, &action, &mut previous));
                let after = run_on(&stack, || {
                    leave_a_mark();
                    libc::pthread_kill(libc::pthread_self(), libc::SIGUSR2);
                    leave_a_mark()
                })
                .expect("no panic");
                libc::sigaction(libc::SIGUSR2, &previous, std::ptr::null_mut());
                after
            };
            let handled_at = HANDLER_FRAME.load(Ordering::SeqCst);
            assert!(
                holds(&stack, handled_at),
                "the handler ran at {handled_at:#x}"
            );
            assert!(holds(&stack, after));
            assert_eq!(
                0,
                not_zero(&stack),
                "the signal frame is erased with the rest"
            );
        }

        /// The unwind information of the switch lets a backtrace taken inside the work be
        /// walked without harm.
        #[test]
        fn a_backtrace_can_be_taken_inside_the_work() {
            let frames = run(|| std::backtrace::Backtrace::force_capture().to_string());
            assert!(!frames.is_empty());
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
