//! [`RedisDbIndex`]: the logical database a `kind: redis` database entry
//! names.

/// A Redis logical database index, parsed from `databases[].name`. Only the
/// canonical decimal spelling parses (`"3"`, never `"03"` or `"+3"`), so one
/// index has exactly one grant address (`server/3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedisDbIndex(u32);

impl RedisDbIndex {
    pub fn parse(name: &str) -> Option<Self> {
        let index: u32 = name.parse().ok()?;
        (index.to_string() == name).then_some(Self(index))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_canonical_decimal_spelling_parses() {
        assert_eq!(RedisDbIndex::parse("0").map(RedisDbIndex::get), Some(0));
        assert_eq!(RedisDbIndex::parse("15").map(RedisDbIndex::get), Some(15));
        for bad in ["", "app", "-1", "+1", "01", " 1", "1 ", "1.0", "4294967296"] {
            assert_eq!(RedisDbIndex::parse(bad), None, "{bad:?}");
        }
    }
}
