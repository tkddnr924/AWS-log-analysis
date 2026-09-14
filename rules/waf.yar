// Baseline WAF (wafv2) detections. The action and the terminating rule are
// stored under `response`; the request under `request`.

rule waf_blocked_request
{
    meta:
        description = "WAF blocked a request"
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
        description = "WAF blocked a request matching an injection rule set (SQLi/XSS)"
        severity    = "high"
        log_type    = "waf_acl"

    fields:
        $action = event_name == "BLOCK"
        $rule   = response.terminating_rule_id icontains "SQLi"
        $xss    = response.terminating_rule_id icontains "XSS"

    condition:
        $action and ($rule or $xss)
}
