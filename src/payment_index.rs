//! Shared conservative handling of payment output indexes.
//! Floating-point JSON values are unsupported: serde_json's default parsing
//! can round a decimal differently from JavaScript before this code sees it.
//! Even with this crate's precise parser, a caller may supply a Value parsed elsewhere.
use serde_json::Value;
pub(crate) const MAX_SAFE_INDEX: u64 = 9_007_199_254_740_991;
/// Ok(Some) is a nonnegative safe integer, Ok(None) is an invalid non-float,
/// and Err means a floating-point representation requires JS-compatible parse.
pub(crate) fn safe_index(value: Option<&Value>) -> Result<Option<u64>, ()> {
    let Some(Value::Number(number)) = value else {
        return Ok(None);
    };
    if let Some(n) = number.as_u64() {
        return Ok((n <= MAX_SAFE_INDEX).then_some(n));
    }
    if number.as_i64().is_some() {
        return Ok(None);
    }
    Err(())
}
