//! MCP protocol vocabulary shared by the transport and the tools: the
//! JSON-RPC 2.0 envelope and the MCP payload types + tool names. Pure data, no
//! I/O — both layers import it, so neither depends on the other for framing.

pub mod jsonrpc;
pub mod protocol;
mod tool_list;
