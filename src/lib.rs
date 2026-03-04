//! Harness macro for multi-engine fuzzing.
//!
//! Provides the [`fuzz!`] macro which delegates to the appropriate fuzzing
//! engine based on enabled features:
//! - No feature: reads a file from argv and passes bytes to the closure (runner mode)
//! - `afl` feature: delegates to `afl::fuzz!`, falls back to file runner if args present
//! - `honggfuzz` feature: wraps `honggfuzz::fuzz!` in a loop

#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;
#[cfg(feature = "libfuzzer")]
#[doc(hidden)]
pub extern crate libfuzzer_sys;

/// Drives the libfuzzer runtime from the user's main().
#[cfg(feature = "libfuzzer")]
#[doc(hidden)]
pub fn __libfuzzer_run(callback: extern "C" fn(*const u8, usize) -> std::os::raw::c_int) -> ! {
    extern "C" {
        fn LLVMFuzzerRunDriver(
            argc: *mut std::os::raw::c_int,
            argv: *mut *const *const std::os::raw::c_char,
            callback: extern "C" fn(*const u8, usize) -> std::os::raw::c_int,
        ) -> std::os::raw::c_int;
    }

    // Install aborting panic hook (same as libfuzzer_sys::initialize).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::abort();
    }));

    let args: Vec<std::ffi::CString> = std::env::args()
        .map(|a| std::ffi::CString::new(a).unwrap())
        .collect();
    let c_args: Vec<*const std::os::raw::c_char> = args.iter().map(|a| a.as_ptr()).collect();
    let mut argc = c_args.len() as std::os::raw::c_int;
    let mut argv = c_args.as_ptr();
    unsafe {
        let code = LLVMFuzzerRunDriver(&mut argc, &mut argv, callback);
        std::process::exit(code);
    }
}

/// Opens a file given as the first CLI argument and feeds its contents to the
/// harness closure. Used as the runner backend when no fuzzing engine is active.
#[doc(hidden)]
pub fn run_file<F>(mut closure: F)
where
    F: FnMut(&[u8]),
{
    use std::{env, fs::File, io::Read};
    let file_name: String = env::args().nth(1).expect("pass in a file name as argument");
    println!("Now running {file_name}");
    let mut buffer: Vec<u8> = Vec::new();
    let mut file = File::open(file_name).unwrap_or_else(|e| {
        eprintln!("Could not open file: {e}");
        std::process::exit(1);
    });
    file.read_to_end(&mut buffer).unwrap_or_else(|e| {
        eprintln!("Could not read file: {e}");
        std::process::exit(1);
    });
    closure(buffer.as_slice());
}

/// Inner harness that dispatches on the closure argument type.
#[macro_export]
#[doc(hidden)]
macro_rules! inner_fuzz {
    (|$buf:ident| $body:block) => {
        $crate::run_file(|$buf| $body);
    };
    (|$buf:ident: &[u8]| $body:block) => {
        $crate::run_file(|$buf| $body);
    };
    (|$buf:ident: $dty:ty| $body:block) => {
        $crate::run_file(|$buf| {
            let $buf: $dty = {
                let mut data = ::arbitrary::Unstructured::new($buf);
                if let Ok(d) = ::arbitrary::Arbitrary::arbitrary(&mut data).map_err(|_| "") {
                    d
                } else {
                    return;
                }
            };
            $body
        });
    };
}

/// libfuzzer variant: calls LLVMFuzzerRunDriver from the user's main().
#[macro_export]
#[cfg(feature = "libfuzzer")]
macro_rules! fuzz {
    (|$bytes:ident| $body:block) => {
        $crate::fuzz!(|$bytes: &[u8]| $body);
    };
    (|$bytes:ident: &[u8]| $body:block) => {{
        extern "C" fn __libfuzzer_callback(data: *const u8, size: usize) -> ::std::os::raw::c_int {
            let $bytes: &[u8] = unsafe { ::std::slice::from_raw_parts(data, size) };
            $body;
            0
        }
        $crate::__libfuzzer_run(__libfuzzer_callback);
    }};
    (|$data:ident: $dty:ty| $body:block) => {{
        extern "C" fn __libfuzzer_callback(data: *const u8, size: usize) -> ::std::os::raw::c_int {
            use $crate::libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
            let bytes: &[u8] = unsafe { ::std::slice::from_raw_parts(data, size) };
            if bytes.len() < <$dty as Arbitrary>::size_hint(0).0 {
                return -1;
            }
            let $data: $dty =
                match <$dty as Arbitrary>::arbitrary_take_rest(Unstructured::new(bytes)) {
                    Ok(d) => d,
                    Err(_) => return -1,
                };
            $body;
            0
        }
        $crate::__libfuzzer_run(__libfuzzer_callback);
    }};
}

/// Runner-only variant: reads a file and feeds it to the harness.
#[macro_export]
#[cfg(not(any(feature = "afl", feature = "honggfuzz", feature = "libfuzzer")))]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        $crate::inner_fuzz!($($x)*);
    }
}

/// AFL++ variant: uses `afl::fuzz!` unless a file argument is present.
#[macro_export]
#[cfg(feature = "afl")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        static USE_ARGS: std::sync::LazyLock<bool> =
            std::sync::LazyLock::new(|| std::env::args().len() > 1);
        if *USE_ARGS {
            $crate::inner_fuzz!($($x)*);
        } else {
            $crate::afl_fuzz!($($x)*);
        }
    };
}

/// Honggfuzz variant: wraps the harness in a loop for persistent mode.
#[macro_export]
#[cfg(feature = "honggfuzz")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        loop {
            $crate::honggfuzz_fuzz!($($x)*);
        }
    };
}
