//! Normalized event model. Rules bind to these field names, not to raw
//! CloudTrail JSON paths, so a rule survives new log types
//! (docs/04-rule-format.md).

use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq)]
pub struct NormalizedEvent {
    pub file_id: u32,
    /// Position within the source file; with `file_id` it locates the original.
    pub record_index: u64,
    pub event_time: Option<OffsetDateTime>,
    pub event_source: Option<String>,
    pub event_name: Option<String>,
    pub aws_region: Option<String>,
    pub account_id: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub identity_type: Option<String>,
    pub identity_arn: Option<String>,
    pub identity_name: Option<String>,
    pub mfa_authenticated: Option<bool>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub read_only: Option<bool>,
    pub management_event: Option<bool>,
    /// Service-specific shapes stay as JSON text; rules address them dynamically.
    pub request: Option<String>,
    pub response: Option<String>,
    pub resources: Option<String>,
    pub raw: Option<String>,
}
