// Baseline ALB access-log detections. Parsed request and response attributes
// are stored under the normalized dynamic JSON fields.

rule alb_server_error
{
    meta:
        name        = "서버 오류 (5xx)"
        description = "ALB returned a server error"
        severity    = "medium"
        log_type    = "alb_access"

    fields:
        $status = response.elb_status_code >= 500

    condition:
        $status
}

rule alb_forbidden_request
{
    meta:
        name        = "접근 거부 (403)"
        description = "ALB rejected a request with HTTP 403"
        severity    = "low"
        log_type    = "alb_access"

    fields:
        $status = error_code == "HTTP 403"

    condition:
        $status
}

rule alb_unusual_http_method
{
    meta:
        name        = "비정상 HTTP 메서드 (CONNECT·TRACE)"
        description = "ALB received an unusual proxy-oriented HTTP method"
        severity    = "high"
        log_type    = "alb_access"

    fields:
        $method = event_name in ("CONNECT", "TRACE")

    condition:
        $method
}
