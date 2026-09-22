// Baseline API Gateway access-log detections.

rule apigw_server_error
{
    meta:
        name        = "서버 오류 (5xx)"
        description = "API Gateway returned a server error"
        severity    = "medium"
        log_type    = "apigw_access"

    fields:
        $status = response.status >= 500
        $upper = response.status < 600

    condition:
        $status and $upper
}
