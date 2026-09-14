//! Fixture builders. All sample data is synthetic — no real account values.
//! Each test binary includes this module and uses only part of it.
#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::Path;

use flate2::write::GzEncoder;
use flate2::Compression;

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

/// Two gzip members concatenated, as produced by some S3 export pipelines.
pub fn gzip_multi_member(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| gzip(p)).collect()
}

pub fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

/// Minimal CloudTrail record with masked identifiers.
pub fn cloudtrail_record(event_name: &str) -> String {
    format!(
        r#"{{
            "eventVersion": "1.08",
            "eventTime": "2026-09-11T02:03:04Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "{event_name}",
            "awsRegion": "ap-northeast-2",
            "sourceIPAddress": "203.0.113.10",
            "userAgent": "Mozilla/5.0",
            "recipientAccountId": "000000000000",
            "userIdentity": {{
                "type": "IAMUser",
                "arn": "arn:aws:iam::000000000000:user/masked",
                "userName": "masked"
            }},
            "responseElements": {{"ConsoleLogin": "Failure"}},
            "readOnly": false,
            "managementEvent": true
        }}"#
    )
}

pub fn cloudtrail_json(records: &[String]) -> String {
    format!(r#"{{"Records":[{}]}}"#, records.join(","))
}

/// One WAF v2 log line, masked. `action`/`rule` shape the block case.
pub fn waf_record(action: &str, rule: &str) -> String {
    format!(
        r#"{{"timestamp":1788146539583,"formatVersion":1,"webaclId":"arn:aws:wafv2:ap-northeast-2:000000000000:regional/webacl/masked-acl/00000000-0000-0000-0000-000000000000","terminatingRuleId":"{rule}","terminatingRuleType":"MANAGED_RULE_GROUP","action":"{action}","terminatingRuleMatchDetails":[{{"conditionType":"SQL_INJECTION","location":"ALL_QUERY_ARGS","matchedData":["Aloe","Extract"],"matchedFieldName":"query"}}],"httpSourceName":"APIGW","httpSourceId":"000000000000:masked:prd","ruleGroupList":[],"rateBasedRuleList":[],"nonTerminatingMatchingRules":[],"requestHeadersInserted":null,"responseCodeSent":null,"httpRequest":{{"clientIp":"203.0.113.10","country":"KR","headers":[{{"name":"host","value":"api.example.test"}},{{"name":"user-agent","value":"Mozilla/5.0 masked"}}],"uri":"/v1/search","args":"query=Aloe%20Extract","httpVersion":"HTTP/1.1","httpMethod":"OPTIONS","requestId":"MASKEDREQ="}},"labels":[{{"name":"awswaf:managed:aws:sql-database:SQLi_QueryArguments"}}]}}"#
    )
}

/// One API Gateway access-log line (custom JSON access format), masked.
pub fn apigw_record(status: u16) -> String {
    format!(
        r#"{{"request_id":"00000000-0000-0000-0000-000000000001","ip":"203.0.113.20","caller":"-","user":"-","request_time":"31/Aug/2026:00:00:05 +0000","http_method":"GET","resource_path":"/v1/items","path":"/v1/items?page=2","status":"{status}","protocol":"HTTP/1.1","response_length":"1392","integration_status":"{status}","integration_latency":"6","user_agent":"okhttp/4.12.0","api_id":"masked0api","stage":"prd"}}"#
    )
}

/// One nginx access record as exported from Elasticsearch, masked.
pub fn nginx_record(status: u16) -> String {
    format!(
        r#"{{"_index":"nginx-2026.08.31","_id":"masked","_source":{{"@timestamp":"2026-08-31T06:24:00.004Z","event":{{"dataset":"nginx.access"}},"service":{{"name":"masked-api","environment":"prd"}},"trace":{{"id":"01e9cd8ae5dc209ed181ceaa7f141a39"}},"birdview":{{"request_method":"GET","status":"{status}","client_ip":"203.0.113.30","remote_addr":"10.0.0.9","host":"api.example.test","request_uri":"/v1/products/1","http_user_agent":"node","http_referer":"-","server_protocol":"HTTP/1.1","bytes_sent":48183,"body_bytes_sent":47732,"request_time":0.096,"upstream_response_time":0.096}}}}}}"#
    )
}
