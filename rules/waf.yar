// Baseline WAF (wafv2) detections. The action and the terminating rule are
// stored under `response`; the request under `request`.

rule waf_blocked_request
{
    meta:
        name        = "차단 요청"
        description = "WAF terminating action was BLOCK; enforcement is not proof of an attack or compromise"
        severity    = "medium"
        log_type    = "waf_acl"

    fields:
        $action = event_name == "BLOCK"

    condition:
        $action
}

rule waf_injection_block
{
    meta:
        name        = "인젝션 관련 차단 (SQLi·XSS)"
        description = "WAF blocked a request with SQLi/XSS match details or a SQLi/XSS-named terminating rule; rule names alone remain a heuristic, not proof of compromise"
        severity    = "high"
        log_type    = "waf_acl"

    fields:
        $action = event_name == "BLOCK"
        $rule   = response.terminating_rule_id icontains "SQLi"
        $xss    = response.terminating_rule_id icontains "XSS"
        $sqli_match = response.match_details contains "\"conditionType\":\"SQL_INJECTION\""
        $xss_match  = response.match_details contains "\"conditionType\":\"XSS\""

    condition:
        $action and ($rule or $xss or $sqli_match or $xss_match)
}
