// Baseline nginx access-log detections.

rule nginx_server_error
{
    meta:
        description = "nginx returned a server error"
        severity    = "medium"
        log_type    = "nginx_access"

    fields:
        $status = response.status >= 500

    condition:
        $status
}
