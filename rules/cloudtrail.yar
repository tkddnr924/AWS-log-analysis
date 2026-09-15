// Baseline CloudTrail detections. Field names come from
// docs/04-rule-format.md; `request.*`/`response.*` are dynamic paths.

rule cloudtrail_root_console_login
{
    meta:
        name        = "루트 계정 콘솔 로그인"
        description = "Root account signed in to the console"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $name = event_name    == "ConsoleLogin"
        $root = identity_type == "Root"

    condition:
        $name and $root
}

rule cloudtrail_console_login_failure
{
    meta:
        name        = "콘솔 로그인 실패"
        description = "Failed console login"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "signin.amazonaws.com"
        $name = event_name   == "ConsoleLogin"
        $fail = response.ConsoleLogin == "Failure"

    condition:
        $src and $name and $fail
}

rule cloudtrail_login_without_mfa
{
    meta:
        name        = "MFA 없는 콘솔 로그인"
        description = "Console login without MFA"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $name = event_name == "ConsoleLogin"
        $mfa  = mfa_authenticated == false

    condition:
        $name and $mfa
}

rule cloudtrail_access_denied
{
    meta:
        name        = "권한 거부 (AccessDenied)"
        description = "Authorization failure — possible enumeration"
        severity    = "low"
        log_type    = "cloudtrail"

    fields:
        $denied = error_code matches /AccessDenied|UnauthorizedOperation/

    condition:
        $denied
}

rule cloudtrail_trail_tampering
{
    meta:
        name        = "CloudTrail 로깅 중지·삭제·변경"
        description = "CloudTrail logging stopped or deleted"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "cloudtrail.amazonaws.com"
        $name = event_name in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors")

    condition:
        $src and $name
}

rule cloudtrail_long_lived_session
{
    meta:
        name        = "비정상적으로 긴 AssumeRole 세션"
        description = "AssumeRole requesting an unusually long session"
        severity    = "low"
        log_type    = "cloudtrail"

    fields:
        $name     = event_name == "AssumeRole"
        $duration = request.durationSeconds > 14400

    condition:
        $name and $duration
}

rule cloudtrail_root_api_activity
{
    meta:
        name        = "루트 계정 API 사용"
        description = "Root account used outside a console login"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $root  = identity_type == "Root"
        $login = event_name    == "ConsoleLogin"

    condition:
        $root and not $login
}

rule cloudtrail_iam_policy_change
{
    meta:
        name        = "IAM 정책 변경"
        description = "IAM identity policy or policy version changed"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "iam.amazonaws.com"
        $name = event_name in ("AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "SetDefaultPolicyVersion")

    condition:
        $src and $name
}

rule cloudtrail_access_key_created
{
    meta:
        name        = "IAM 액세스 키 생성"
        description = "A new IAM access key was created"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "iam.amazonaws.com"
        $name = event_name   == "CreateAccessKey"

    condition:
        $src and $name
}

rule cloudtrail_kms_key_disruption
{
    meta:
        name        = "KMS 키 비활성화·삭제 예약"
        description = "KMS key disabled or scheduled for deletion"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "kms.amazonaws.com"
        $name = event_name in ("DisableKey", "ScheduleKeyDeletion")

    condition:
        $src and $name
}

rule cloudtrail_monitoring_disabled
{
    meta:
        name        = "GuardDuty·Security Hub 해제"
        description = "GuardDuty or Security Hub monitoring was disabled"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $guardduty  = event_source == "guardduty.amazonaws.com"
        $security   = event_source == "securityhub.amazonaws.com"
        $disruption = event_name in ("DeleteDetector", "DisableSecurityHub")

    condition:
        ($guardduty or $security) and $disruption
}
