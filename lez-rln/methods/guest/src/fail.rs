//! Failing a check by halting with an exit code instead of panicking.
//!
//! LEZ charges a panicking guest the transaction's full declared gas, but a
//! guest that halts with a non-zero code only the cycles it ran. [`ensure!`]
//! is for checks an honest client can fail because the chain moved after it
//! read it (codes in `rln_layouts::exit`); checks only a malformed or hostile
//! transaction can fail stay `assert!`s, and keep the full charge.
//!
//! Off the zkVM (the guest unit tests) there is no `env::exit`, so [`fail`]
//! panics with `"exit {code}: {msg}"`, which `#[should_panic(expected)]`
//! matches by message as before.

/// Log `msg` and halt the session with `code`. Never returns.
pub fn fail(code: u8, msg: &str) -> ! {
    #[cfg(target_os = "zkvm")]
    {
        risc0_zkvm::guest::env::log(msg);
        risc0_zkvm::guest::env::exit(code)
    }
    #[cfg(not(target_os = "zkvm"))]
    panic!("exit {code}: {msg}")
}

/// `ensure!(cond, code, "fmt", args..)`: unless `cond`, [`fail`] with `code`
/// and the formatted message. The message is formatted only on failure.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $code:expr, $($msg:tt)+) => {
        if !$cond {
            $crate::fail::fail($code, &::std::format!($($msg)+))
        }
    };
}

#[cfg(test)]
mod tests {
    #[test]
    #[should_panic(expected = "exit 10: clock moved to 5")]
    fn ensure_fails_with_code_and_message() {
        ensure!(1 + 1 == 3, 10, "clock moved to {}", 5);
    }

    #[test]
    fn ensure_passes_when_true() {
        ensure!(true, 10, "unreachable");
    }
}
