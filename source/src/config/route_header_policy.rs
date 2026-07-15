//! Shared header mutation policy for route-level actions.
//! Request-side route actions cannot override proxy-owned identity metadata.

pub(crate) use oxibelt_control_protocol::is_forbidden_route_action_header;
pub use oxibelt_control_protocol::{
  is_reserved_route_request_header, normalize_route_action_header_name,
};
