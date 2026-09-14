//! Field mapping: which JSON path feeds each stored column.
//!
//! CloudTrail is the default shape, but exports are not uniform — organisations
//! post-process them, and other AWS services use different key names. Rather
//! than hard-coding the shape in the parser, the mapping is data the user can
//! inspect and override before a run (docs/03).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A column the rule engine and results UI can address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    EventTime,
    EventSource,
    EventName,
    AwsRegion,
    AccountId,
    SourceIp,
    UserAgent,
    IdentityType,
    IdentityArn,
    IdentityName,
    MfaAuthenticated,
    ErrorCode,
    ErrorMessage,
    ReadOnly,
    ManagementEvent,
    Request,
    Response,
    Resources,
}

impl Field {
    /// Every field, in the order the mapping editor shows them.
    pub const ALL: [Field; 18] = [
        Field::EventTime,
        Field::EventName,
        Field::EventSource,
        Field::AwsRegion,
        Field::AccountId,
        Field::SourceIp,
        Field::UserAgent,
        Field::IdentityType,
        Field::IdentityArn,
        Field::IdentityName,
        Field::MfaAuthenticated,
        Field::ErrorCode,
        Field::ErrorMessage,
        Field::ReadOnly,
        Field::ManagementEvent,
        Field::Request,
        Field::Response,
        Field::Resources,
    ];

    /// Stable key used in `mapping.json` and over the IPC boundary.
    pub fn key(self) -> &'static str {
        match self {
            Field::EventTime => "event_time",
            Field::EventSource => "event_source",
            Field::EventName => "event_name",
            Field::AwsRegion => "aws_region",
            Field::AccountId => "account_id",
            Field::SourceIp => "source_ip",
            Field::UserAgent => "user_agent",
            Field::IdentityType => "identity_type",
            Field::IdentityArn => "identity_arn",
            Field::IdentityName => "identity_name",
            Field::MfaAuthenticated => "mfa_authenticated",
            Field::ErrorCode => "error_code",
            Field::ErrorMessage => "error_message",
            Field::ReadOnly => "read_only",
            Field::ManagementEvent => "management_event",
            Field::Request => "request",
            Field::Response => "response",
            Field::Resources => "resources",
        }
    }

    pub fn from_key(key: &str) -> Option<Field> {
        Field::ALL.into_iter().find(|f| f.key() == key)
    }

    /// Display name. Lives here so the rule explanation, the results table,
    /// the detail view and the mapping editor all call a field the same
    /// thing; a second copy in the UI would drift.
    pub fn label(self) -> &'static str {
        match self {
            Field::EventTime => "이벤트 시각",
            Field::EventSource => "서비스",
            Field::EventName => "이벤트 이름",
            Field::AwsRegion => "리전",
            Field::AccountId => "계정 ID",
            Field::SourceIp => "출발지 IP",
            Field::UserAgent => "User-Agent",
            Field::IdentityType => "주체 유형",
            Field::IdentityArn => "주체 ARN",
            Field::IdentityName => "주체 이름",
            Field::MfaAuthenticated => "MFA 사용",
            Field::ErrorCode => "오류 코드",
            Field::ErrorMessage => "오류 메시지",
            Field::ReadOnly => "읽기 전용",
            Field::ManagementEvent => "관리 이벤트",
            Field::Request => "요청 파라미터",
            Field::Response => "응답 요소",
            Field::Resources => "대상 리소스",
        }
    }

    /// Paths tried in order. Several fields legitimately live in more than one
    /// place: `mfaAuthenticated` is a session attribute for assumed roles but
    /// `additionalEventData.MFAUsed` for ConsoleLogin.
    pub fn default_sources(self) -> &'static [&'static str] {
        match self {
            Field::EventTime => &["eventTime"],
            Field::EventSource => &["eventSource"],
            Field::EventName => &["eventName"],
            Field::AwsRegion => &["awsRegion"],
            Field::AccountId => &["recipientAccountId"],
            Field::SourceIp => &["sourceIPAddress"],
            Field::UserAgent => &["userAgent"],
            Field::IdentityType => &["userIdentity.type"],
            Field::IdentityArn => &["userIdentity.arn"],
            Field::IdentityName => &[
                "userIdentity.userName",
                "userIdentity.sessionContext.sessionIssuer.userName",
            ],
            Field::MfaAuthenticated => &[
                "userIdentity.sessionContext.attributes.mfaAuthenticated",
                "additionalEventData.MFAUsed",
            ],
            Field::ErrorCode => &["errorCode"],
            Field::ErrorMessage => &["errorMessage"],
            Field::ReadOnly => &["readOnly"],
            Field::ManagementEvent => &["managementEvent"],
            Field::Request => &["requestParameters"],
            Field::Response => &["responseElements"],
            Field::Resources => &["resources"],
        }
    }
}

/// User-editable source paths per field. Absent entries fall back to the
/// CloudTrail defaults, so a partial mapping only overrides what it names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldMap {
    #[serde(flatten)]
    overrides: BTreeMap<String, Vec<String>>,
}

impl FieldMap {
    /// The built-in CloudTrail mapping, spelled out. Used as the editor's
    /// starting point so the user sees real paths rather than an empty form.
    pub fn cloudtrail() -> Self {
        Self {
            overrides: Field::ALL
                .into_iter()
                .map(|f| {
                    (
                        f.key().to_owned(),
                        f.default_sources()
                            .iter()
                            .map(|s| (*s).to_owned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }

    pub fn set(&mut self, field: Field, sources: Vec<String>) {
        self.overrides.insert(field.key().to_owned(), sources);
    }

    /// Paths to try for `field`, user-specified or default.
    pub fn sources(&self, field: Field) -> Vec<&str> {
        match self.overrides.get(field.key()) {
            Some(paths) => paths.iter().map(String::as_str).collect(),
            None => field.default_sources().to_vec(),
        }
    }

    /// First path that yields a value. Missing paths are not errors: an
    /// absent field is simply absent (docs/04 "평가는 오류를 만들지 않음").
    pub fn lookup<'a>(&self, record: &'a Value, field: Field) -> Option<&'a Value> {
        self.lookup_with(record, field, Some)
    }

    /// First path whose value survives `coerce`. Coercion is inside the
    /// fallback loop on purpose: a bool field whose first path holds an
    /// unparseable string must fall through to the next path, not give up.
    pub fn lookup_with<'a, T>(
        &self,
        record: &'a Value,
        field: Field,
        coerce: impl Fn(&'a Value) -> Option<T>,
    ) -> Option<T> {
        self.sources(field).into_iter().find_map(|path| {
            resolve(record, path)
                .filter(|value| !value.is_null())
                .and_then(&coerce)
        })
    }
}

/// CloudTrail spells booleans three ways: real bools, "true"/"false", and
/// "Yes"/"No" for `additionalEventData.MFAUsed`.
pub fn as_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.as_str() {
            "Yes" => Some(true),
            "No" => Some(false),
            other => other.parse().ok(),
        },
        _ => None,
    }
}

/// Walks a dotted path. Numeric segments index arrays, so `resources.0.type`
/// reaches into the list CloudTrail attaches to data events.
pub fn resolve<'a>(record: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = record;
    for segment in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(segment)?,
            Value::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}
