// Baseline nginx access-log detections.

rule nginx_server_error
{
    meta:
        name        = "서버 오류 (5xx)"
        description = "nginx returned a server error"
        severity    = "medium"
        log_type    = "nginx_access"

    fields:
        $status = response.status >= 500
        $upper = response.status < 600

    condition:
        $status and $upper
}
