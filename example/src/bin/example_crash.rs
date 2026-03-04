use multifuzz::fuzz;

/// A buggy calculator that crashes on division by zero.
///
/// Input: 3 bytes — [a, b, op].
/// When op == b'/' and b == 0, the program panics.
fn main() {
    fuzz!(|data: &[u8]| {
        if data.len() >= 3 {
            let a = data[0] as u32;
            let b = data[1] as u32;
            let op = data[2];

            let _result = match op {
                b'+' => a + b,
                b'-' => a - b,
                b'*' => a * b,
                b'/' => a / b,
                _ => 0,
            };
        }
    });
}
