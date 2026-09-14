//! Line-delimited JSON logs: WAF (wafv2), API Gateway access logs and nginx
//! access logs exported from Elasticsearch/filebeat. One record per line,
//! recognised by their keys and folded onto the normalized event columns.

use serde::Serialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::OffsetDateTime;

use crate::detect::{LogType, SampleRecord};
use crate::model::NormalizedEvent;

/// Which producer wrote this record, judged by keys no other format shares.
pub fn classify(value: &Value) -> Option<LogType> {
    let obj = value.as_object()?;
    if obj.contains_key("webaclId") && obj.contains_key("httpRequest") && obj.contains_key("action")
    {
        return Some(LogType::WafAcl);
    }
    if obj.contains_key("request_id")
        && obj.contains_key("resource_path")
        && obj.contains_key("http_method")
    {
        return Some(LogType::ApigwAccess);
    }
    // Elasticsearch document export: the record sits under `_source`.
    let source = obj.get("_source").and_then(Value::as_object).unwrap_or(obj);
    let dataset = source
        .get("event")
        .and_then(|e| e.get("dataset"))
        .and_then(Value::as_str);
    if dataset == Some("nginx.access") || source.contains_key("birdview") {
        return Some(LogType::NginxAccess);
    }
    None
}

/// The head-of-file summary shown before parsing (FR-4).
pub fn sample(log_type: LogType, value: &Value) -> SampleRecord {
    let fields = Fields::extract(log_type, value);
    SampleRecord {
        raw: Some(value.to_string()),
        event_time: fields.time.map(|t| t.format(&Rfc3339).unwrap_or_default()),
        event_source: Some(source_of(log_type).to_owned()),
        event_name: fields.name.map(str::to_owned),
        aws_region: fields.region.map(str::to_owned),
        source_ip_address: fields.source_ip.map(str::to_owned),
        ..Default::default()
    }
}

/// One line into a normalized event. `Err` marks a malformed line the caller
/// counts and skips.
pub(crate) fn normalize(
    log_type: LogType,
    line: &str,
    file_id: u32,
    record_index: u64,
    keep_raw: bool,
) -> Result<NormalizedEvent, ()> {
    let value: Value = serde_json::from_str(line).map_err(|_| ())?;
    let f = Fields::extract(log_type, &value);
    let (request, response, resources) = match log_type {
        LogType::WafAcl => waf_json(&value, &f)?,
        LogType::ApigwAccess => apigw_json(&value, &f)?,
        LogType::NginxAccess => nginx_json(&value, &f)?,
        _ => return Err(()),
    };
    let method_or_action = f.name.map(str::to_owned);
    Ok(NormalizedEvent {
        file_id,
        record_index,
        event_time: f.time,
        event_source: Some(source_of(log_type).to_owned()),
        event_name: method_or_action,
        aws_region: f.region.map(str::to_owned),
        account_id: f.account.map(str::to_owned),
        source_ip: f.source_ip.map(str::to_owned),
        user_agent: f.user_agent.map(str::to_owned),
        identity_type: None,
        identity_arn: None,
        identity_name: None,
        mfa_authenticated: None,
        error_code: f.error_code,
        error_message: None,
        read_only: f.method.map(|m| matches!(m, "GET" | "HEAD" | "OPTIONS")),
        management_event: Some(false),
        request: Some(request),
        response: Some(response),
        resources: Some(resources),
        raw: keep_raw.then(|| line.to_owned()),
    })
}

fn source_of(log_type: LogType) -> &'static str {
    match log_type {
        LogType::WafAcl => "wafv2.amazonaws.com",
        LogType::ApigwAccess => "apigateway.amazonaws.com",
        LogType::NginxAccess => "nginx",
        other => other.as_str(),
    }
}

/// The handful of values every producer has, pulled out once for both the
/// summary and the normalized columns.
#[derive(Default)]
struct Fields<'a> {
    time: Option<OffsetDateTime>,
    /// WAF action or HTTP method.
    name: Option<&'a str>,
    method: Option<&'a str>,
    region: Option<&'a str>,
    account: Option<&'a str>,
    source_ip: Option<&'a str>,
    user_agent: Option<&'a str>,
    status: Option<u16>,
    error_code: Option<String>,
}

impl<'a> Fields<'a> {
    fn extract(log_type: LogType, v: &'a Value) -> Self {
        match log_type {
            LogType::WafAcl => {
                let req = v.get("httpRequest");
                let action = v.get("action").and_then(Value::as_str);
                let rule = v.get("terminatingRuleId").and_then(Value::as_str);
                // arn:aws:wafv2:<region>:<account>:regional/webacl/...
                let mut arn = v
                    .get("webaclId")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .split(':')
                    .skip(3);
                Self {
                    time: v.get("timestamp").and_then(Value::as_i64).and_then(|ms| {
                        OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()
                    }),
                    name: action,
                    method: req
                        .and_then(|r| r.get("httpMethod"))
                        .and_then(Value::as_str),
                    region: arn.next(),
                    account: arn.next(),
                    source_ip: req.and_then(|r| r.get("clientIp")).and_then(Value::as_str),
                    user_agent: header(req, "user-agent"),
                    status: None,
                    // Only a block is an "error" from the caller's side; a
                    // rule that merely counted is not.
                    error_code: (action == Some("BLOCK"))
                        .then(|| rule.map(str::to_owned))
                        .flatten(),
                }
            }
            LogType::ApigwAccess => {
                let status = str_or_num(v.get("status"));
                Self {
                    time: v
                        .get("request_time")
                        .and_then(Value::as_str)
                        .and_then(parse_clf_time),
                    name: v.get("http_method").and_then(Value::as_str),
                    method: v.get("http_method").and_then(Value::as_str),
                    region: None,
                    account: None,
                    source_ip: v.get("ip").and_then(Value::as_str),
                    user_agent: v.get("user_agent").and_then(Value::as_str),
                    status,
                    error_code: http_error(status),
                }
            }
            LogType::NginxAccess => {
                let src = v.get("_source").unwrap_or(v);
                let bv = src.get("birdview");
                let status = str_or_num(bv.and_then(|b| b.get("status")));
                let method = bv
                    .and_then(|b| b.get("request_method"))
                    .and_then(Value::as_str);
                Self {
                    time: src
                        .get("@timestamp")
                        .and_then(Value::as_str)
                        .and_then(|t| OffsetDateTime::parse(t, &Rfc3339).ok()),
                    name: method,
                    method,
                    region: None,
                    account: None,
                    source_ip: bv.and_then(|b| b.get("client_ip")).and_then(Value::as_str),
                    user_agent: bv
                        .and_then(|b| b.get("http_user_agent"))
                        .and_then(Value::as_str),
                    status,
                    error_code: http_error(status),
                }
            }
            _ => Self::default(),
        }
    }
}

fn header<'a>(req: Option<&'a Value>, name: &str) -> Option<&'a str> {
    req?.get("headers")?.as_array()?.iter().find_map(|h| {
        let matches = h.get("name")?.as_str()?.eq_ignore_ascii_case(name);
        matches.then(|| h.get("value")?.as_str())?
    })
}

/// Producers disagree on whether a status is `"200"` or `200`.
fn str_or_num(v: Option<&Value>) -> Option<u16> {
    match v? {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        _ => None,
    }
}

fn http_error(status: Option<u16>) -> Option<String> {
    status.filter(|s| *s >= 400).map(|s| format!("HTTP {s}"))
}

/// `31/Aug/2026:00:00:05 +0000`, the CLF timestamp API Gateway writes.
fn parse_clf_time(text: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(
        text,
        format_description!(
            "[day]/[month repr:short]/[year]:[hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
        ),
    )
    .ok()
}

#[derive(Serialize)]
struct Request<'a> {
    method: Option<&'a str>,
    /// Host + path + query where the producer gives them, so `request.url`
    /// reads the same across ALB, WAF, API Gateway and nginx.
    url: Option<String>,
    protocol: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    referer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<&'a str>,
}

fn waf_json(v: &Value, f: &Fields) -> Result<(String, String, String), ()> {
    let req = v.get("httpRequest").ok_or(())?;
    let s = |k: &str| req.get(k).and_then(Value::as_str);
    let uri = s("uri").unwrap_or_default();
    let url = match s("args").filter(|a| !a.is_empty()) {
        Some(args) => format!("{uri}?{args}"),
        None => uri.to_owned(),
    };
    let request = serde_json::to_string(&Request {
        method: f.method,
        url: Some(url),
        protocol: s("httpVersion"),
        request_id: s("requestId"),
        country: s("country"),
        referer: header(Some(req), "referer"),
        trace_id: header(Some(req), "x-amzn-trace-id"),
    })
    .map_err(|_| ())?;
    let response = serde_json::json!({
        "action": v.get("action"),
        "terminating_rule_id": v.get("terminatingRuleId"),
        "terminating_rule_type": v.get("terminatingRuleType"),
        "match_details": v.get("terminatingRuleMatchDetails"),
        "labels": v.get("labels"),
        "response_code_sent": v.get("responseCodeSent"),
    })
    .to_string();
    let resources = serde_json::json!({
        "web_acl_id": v.get("webaclId"),
        "http_source_name": v.get("httpSourceName"),
        "http_source_id": v.get("httpSourceId"),
        "host": header(Some(req), "host"),
    })
    .to_string();
    Ok((request, response, resources))
}

fn apigw_json(v: &Value, f: &Fields) -> Result<(String, String, String), ()> {
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    let request = serde_json::to_string(&Request {
        method: f.method,
        url: s("path").map(str::to_owned),
        protocol: s("protocol"),
        request_id: s("request_id"),
        country: None,
        referer: None,
        trace_id: None,
    })
    .map_err(|_| ())?;
    let response = serde_json::json!({
        "status": f.status,
        "response_length": s("response_length").and_then(|n| n.parse::<u64>().ok()),
        "integration_status": s("integration_status").and_then(|n| n.parse::<u16>().ok()),
        "integration_latency": s("integration_latency").and_then(|n| n.parse::<u64>().ok()),
    })
    .to_string();
    let resources = serde_json::json!({
        "api_id": s("api_id"),
        "stage": s("stage"),
        "resource_path": s("resource_path"),
    })
    .to_string();
    Ok((request, response, resources))
}

fn nginx_json(v: &Value, f: &Fields) -> Result<(String, String, String), ()> {
    let src = v.get("_source").unwrap_or(v);
    let bv = src.get("birdview").ok_or(())?;
    let s = |k: &str| bv.get(k).and_then(Value::as_str);
    let url = match (s("host"), s("request_uri")) {
        (Some(host), Some(uri)) => Some(format!("{host}{uri}")),
        (_, Some(uri)) => Some(uri.to_owned()),
        _ => None,
    };
    let request = serde_json::to_string(&Request {
        method: f.method,
        url,
        protocol: s("server_protocol"),
        request_id: None,
        country: None,
        referer: s("http_referer").filter(|r| *r != "-"),
        trace_id: src
            .get("trace")
            .and_then(|t| t.get("id"))
            .and_then(Value::as_str),
    })
    .map_err(|_| ())?;
    let response = serde_json::json!({
        "status": f.status,
        "bytes_sent": bv.get("bytes_sent"),
        "body_bytes_sent": bv.get("body_bytes_sent"),
        "request_time": bv.get("request_time"),
        "upstream_response_time": bv.get("upstream_response_time"),
    })
    .to_string();
    let resources = serde_json::json!({
        "service": src.get("service").and_then(|x| x.get("name")),
        "environment": src.get("service").and_then(|x| x.get("environment")),
        "host": s("host"),
        "remote_addr": s("remote_addr"),
        "log_path": src.get("log").and_then(|l| l.get("file")).and_then(|f| f.get("path")),
    })
    .to_string();
    Ok((request, response, resources))
}
