//! Protobuf wire bytes, one message at a time. Nothing here recurses.

use super::Unreadable;
use super::schema::{self, NodeType};

/// What a field of a message holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::exec::sql_guard) enum Field {
    Varint,
    Text,
    /// Any one node type, or empty for a NULL.
    Node,
    Message(NodeType),
    /// Never filled in a raw parse tree, or not a field at all.
    Unused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// One message: its type and its bytes.
#[derive(Debug, Clone, Copy)]
pub(in crate::exec::sql_guard) struct Message<'a> {
    pub(in crate::exec::sql_guard) of: NodeType,
    bytes: &'a [u8],
}

impl<'a> Message<'a> {
    pub(in crate::exec::sql_guard) fn new(of: NodeType, bytes: &'a [u8]) -> Self {
        Self { of, bytes }
    }

    #[cfg(test)]
    pub(in crate::exec::sql_guard) fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// The values of field `number`, in order. Looks inside nothing.
    fn values(self, number: u32) -> Result<Vec<Value<'a>>, Unreadable> {
        let mut fields = Fields(self.bytes);
        let mut values = Vec::new();
        while let Some((at, value)) = fields.next()? {
            if at == number {
                values.push(value);
            }
        }
        Ok(values)
    }

    fn one(self, number: u32) -> Result<Option<Value<'a>>, Unreadable> {
        match *self.values(number)?.as_slice() {
            [] => Ok(None),
            [value] => Ok(Some(value)),
            _ => Err(Unreadable::Malformed),
        }
    }

    /// A number; 0 when absent, protobuf's default.
    pub(in crate::exec::sql_guard) fn number(self, number: u32) -> Result<u64, Unreadable> {
        match self.one(number)? {
            None => Ok(0),
            Some(Value::Varint(value)) => Ok(value),
            Some(Value::Bytes(_)) => Err(Unreadable::Malformed),
        }
    }

    /// Text; empty when absent, protobuf's default.
    pub(in crate::exec::sql_guard) fn text(self, number: u32) -> Result<&'a str, Unreadable> {
        match self.one(number)? {
            None => Ok(""),
            Some(Value::Bytes(text)) => {
                std::str::from_utf8(text).map_err(|_| Unreadable::Malformed)
            }
            Some(Value::Varint(_)) => Err(Unreadable::Malformed),
        }
    }

    /// The messages of a field declared as `of`.
    pub(in crate::exec::sql_guard) fn messages(
        self,
        number: u32,
        of: NodeType,
    ) -> Result<Vec<Self>, Unreadable> {
        let message = |value| match value {
            Value::Bytes(bytes) => Ok(Self { of, bytes }),
            Value::Varint(_) => Err(Unreadable::Malformed),
        };
        self.values(number)?.into_iter().map(message).collect()
    }

    /// The nodes of a field, NULLs left out.
    pub(in crate::exec::sql_guard) fn nodes(self, number: u32) -> Result<Vec<Self>, Unreadable> {
        let node = |value| match value {
            Value::Bytes(bytes) => node(bytes).transpose(),
            Value::Varint(_) => Some(Err(Unreadable::Malformed)),
        };
        self.values(number)?.into_iter().filter_map(node).collect()
    }
}

/// What a `Node` holds: exactly one field, its number naming the type.
fn node(bytes: &[u8]) -> Result<Option<Message<'_>>, Unreadable> {
    let mut fields = Fields(bytes);
    let Some((number, value)) = fields.next()? else {
        return Ok(None);
    };
    let (Value::Bytes(bytes), None) = (value, fields.next()?) else {
        return Err(Unreadable::Malformed);
    };
    let of = schema::node(number).ok_or(Unreadable::Node)?;
    Ok(Some(Message { of, bytes }))
}

/// Visit `root` and every message under it, parents first.
pub(in crate::exec::sql_guard) fn walk<'a, E: From<Unreadable>>(
    root: Message<'a>,
    mut visit: impl FnMut(Message<'a>) -> Result<(), E>,
) -> Result<(), E> {
    visit(root)?;
    let mut open = vec![(root.of, Fields(root.bytes))];
    while let Some((of, fields)) = open.last_mut() {
        let Some((number, value)) = fields.next()? else {
            open.pop();
            continue;
        };
        let child = match (declared(*of, number), value) {
            (Field::Varint, Value::Varint(_)) | (Field::Text, Value::Bytes(_)) => None,
            (Field::Node, Value::Bytes(bytes)) => node(bytes)?,
            (Field::Message(of), Value::Bytes(bytes)) => Some(Message { of, bytes }),
            _ => return Err(Unreadable::Malformed.into()),
        };
        if let Some(child) = child {
            visit(child)?;
            open.push((child.of, Fields(child.bytes)));
        }
    }
    Ok(())
}

fn declared(of: NodeType, number: u32) -> Field {
    let index = usize::try_from(number).ok().and_then(|n| n.checked_sub(1));
    index
        .and_then(|i| schema::fields(of).get(i).copied())
        .unwrap_or(Field::Unused)
}

/// The unread rest of one message's fields.
#[derive(Debug)]
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    /// The next field's number and value. A fixed-width or group value is no
    /// field of any message the schema names.
    fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, Unreadable> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let tag = u32::try_from(self.varint()?).map_err(|_| Unreadable::Malformed)?;
        let value = match tag & 7 {
            0 => Value::Varint(self.varint()?),
            2 => Value::Bytes(self.bytes()?),
            _ => return Err(Unreadable::Malformed),
        };
        Ok(Some((tag >> 3, value)))
    }

    fn varint(&mut self) -> Result<u64, Unreadable> {
        let mut value = 0;
        for (i, byte) in self.0.iter().take(10).enumerate() {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                self.0 = &self.0[i + 1..];
                return Ok(value);
            }
        }
        Err(Unreadable::Malformed)
    }

    fn bytes(&mut self) -> Result<&'a [u8], Unreadable> {
        let len = usize::try_from(self.varint()?).map_err(|_| Unreadable::Malformed)?;
        let (bytes, rest) = self.0.split_at_checked(len).ok_or(Unreadable::Malformed)?;
        self.0 = rest;
        Ok(bytes)
    }
}
