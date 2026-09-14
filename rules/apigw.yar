// Baseline API Gateway access-log detections.

rule apigw_server_error
{
    meta:
        description = "API Gateway returned a server error"
        severity    = "medium"
        log_type    = "apigw_access"

    fields:
        $status = response.status >= 500

    condition:
        $status
}
