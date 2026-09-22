// Baseline CloudTrail detections. Field names come from
// docs/04-rule-format.md; `request.*`/`response.*` are dynamic paths.

rule cloudtrail_root_console_login
{
    meta:
        name        = "루트 계정 콘솔 로그인 시도"
        description = "Root console sign-in attempt; inspect response.ConsoleLogin for the outcome"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "signin.amazonaws.com"
        $name = event_name    == "ConsoleLogin"
        $root = identity_type == "Root"

    condition:
        $src and $name and $root
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
        name        = "AWS MFA 미사용으로 기록된 콘솔 로그인 시도"
        description = "Console sign-in attempt with AWS-side MFA recorded false; IdP MFA and login success are not established"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "signin.amazonaws.com"
        $name = event_name == "ConsoleLogin"
        $mfa  = mfa_authenticated == false

    condition:
        $src and $name and $mfa
}

rule cloudtrail_access_denied
{
    meta:
        name        = "권한 거부 (AccessDenied·UnauthorizedOperation)"
        description = "Error code contains AccessDenied or UnauthorizedOperation; ordinary misconfiguration also matches and one denial does not establish enumeration"
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
        name        = "CloudTrail 로깅 중지·삭제·변경 시도"
        description = "CloudTrail logging configuration change attempted; denied calls and legitimate administration are included"
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
        name        = "4시간 초과 AssumeRole 세션 요청"
        description = "STS AssumeRole requested more than 4 hours; role settings may permit this and denied requests also match, not proof of abnormal or issued sessions"
        severity    = "low"
        log_type    = "cloudtrail"

    fields:
        $src      = event_source == "sts.amazonaws.com"
        $name     = event_name == "AssumeRole"
        $duration = request.durationSeconds > 14400

    condition:
        $src and $name and $duration
}

rule cloudtrail_root_api_activity
{
    meta:
        name        = "루트 계정 활동 (ConsoleLogin 제외)"
        description = "Named Root event other than ConsoleLogin; denied calls and sign-in-flow events also match, not proof of completed API effects"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $root  = identity_type == "Root"
        $other = event_name != "ConsoleLogin"

    condition:
        $root and $other
}

rule cloudtrail_iam_policy_change
{
    meta:
        name        = "IAM 정책 변경 시도"
        description = "IAM policy change attempted, excluding targeted AdministratorAccess attachments; not proof of privilege escalation"
        severity    = "medium"
        log_type    = "cloudtrail"

    fields:
        $src  = event_source == "iam.amazonaws.com"
        $name = event_name in ("AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy", "CreatePolicyVersion", "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "SetDefaultPolicyVersion")
        $attach = event_name in ("AttachGroupPolicy", "AttachRolePolicy", "AttachUserPolicy")
        $admin = request.policyArn in ("arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws-us-gov:iam::aws:policy/AdministratorAccess", "arn:aws-cn:iam::aws:policy/AdministratorAccess")

    condition:
        $src and $name and not ($attach and $admin)
}

rule cloudtrail_access_key_created
{
    meta:
        name        = "IAM 액세스 키 생성 시도"
        description = "IAM access key creation attempted; inspect the response and subsequent use before claiming persistence"
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
        name        = "KMS 키 비활성화·삭제 예약 시도"
        description = "KMS key disablement or deletion scheduling attempted; denied calls and approved maintenance are included"
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
        name        = "GuardDuty·Security Hub 중단 시도"
        description = "Monitoring deletion or disablement attempted; denied calls and planned decommissioning are included"
        severity    = "high"
        log_type    = "cloudtrail"

    fields:
        $guardduty  = event_source == "guardduty.amazonaws.com"
        $security   = event_source == "securityhub.amazonaws.com"
        $delete = event_name == "DeleteDetector"
        $update = event_name == "UpdateDetector"
        $off = request.enable == false
        $disable = event_name == "DisableSecurityHub"

    condition:
        ($guardduty and ($delete or ($update and $off))) or ($security and $disable)
}

rule cloudtrail_role_trust_change_attempt
{
    meta:
        name = "역할 신뢰 정책 변경 시도"
        description = "Role trust policy update attempted; review principals and conditions, not proof of external access"
        severity = "high"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "iam.amazonaws.com"
        $name = event_name == "UpdateAssumeRolePolicy"
    condition:
        $src and $name
}

rule cloudtrail_admin_policy_attach_attempt
{
    meta:
        name = "AdministratorAccess 정책 연결 시도"
        description = "AWS managed AdministratorAccess attachment attempted; denied or approved grants are not compromise"
        severity = "high"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "iam.amazonaws.com"
        $name = event_name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy")
        $admin = request.policyArn in ("arn:aws:iam::aws:policy/AdministratorAccess", "arn:aws-us-gov:iam::aws:policy/AdministratorAccess", "arn:aws-cn:iam::aws:policy/AdministratorAccess")
    condition:
        $src and $name and $admin
}

rule cloudtrail_console_profile_change_attempt
{
    meta:
        name = "콘솔 로그인 프로필 생성·변경 시도"
        description = "Console login profile creation or update attempted; includes approved onboarding and password recovery"
        severity = "medium"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "iam.amazonaws.com"
        $name = event_name in ("CreateLoginProfile", "UpdateLoginProfile")
    condition:
        $src and $name
}

rule cloudtrail_mfa_deactivation_attempt
{
    meta:
        name = "MFA 장치 비활성화 시도"
        description = "IAM MFA device deactivation attempted; includes denied calls and legitimate device replacement"
        severity = "high"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "iam.amazonaws.com"
        $name = event_name == "DeactivateMFADevice"
    condition:
        $src and $name
}

rule cloudtrail_ssm_remote_access_attempt
{
    meta:
        name = "SSM 원격 명령·세션 시작 시도"
        description = "SSM command or session start attempted; normal operations also match and execution is not established"
        severity = "medium"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "ssm.amazonaws.com"
        $name = event_name in ("SendCommand", "StartSession")
    condition:
        $src and $name
}

rule cloudtrail_root_console_login_success
{
    meta:
        name = "루트 계정 콘솔 로그인 성공"
        description = "CloudTrail reports a successful root console sign-in; not proof of account compromise"
        severity = "high"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "signin.amazonaws.com"
        $name = event_name == "ConsoleLogin"
        $root = identity_type == "Root"
        $success = response.ConsoleLogin == "Success"
    condition:
        $src and $name and $root and $success
}

rule cloudtrail_login_without_mfa_success
{
    meta:
        name = "AWS MFA 미사용으로 기록된 콘솔 로그인 성공"
        description = "CloudTrail reports successful sign-in with AWS-side MFA false; external IdP MFA is not established"
        severity = "high"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "signin.amazonaws.com"
        $name = event_name == "ConsoleLogin"
        $mfa = mfa_authenticated == false
        $success = response.ConsoleLogin == "Success"
    condition:
        $src and $name and $mfa and $success
}

rule cloudtrail_secret_read_attempt
{
    meta:
        name = "Secrets Manager 비밀값 조회 시도"
        description = "Secret value retrieval attempted, including batch and denied requests; routine application reads also match, not proof of exfiltration"
        severity = "low"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "secretsmanager.amazonaws.com"
        $name = event_name in ("GetSecretValue", "BatchGetSecretValue")
    condition:
        $src and $name
}

rule cloudtrail_parameter_decryption_read_attempt
{
    meta:
        name = "Parameter Store 복호화 요청 조회 시도"
        description = "Parameter retrieval requested with decryption; includes normal configuration reads and denied calls, not proof of decrypted values or exfiltration"
        severity = "low"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "ssm.amazonaws.com"
        $name = event_name in ("GetParameter", "GetParameters", "GetParametersByPath")
        $decrypt = request.withDecryption == true
    condition:
        $src and $name and $decrypt
}

rule cloudtrail_s3_public_access_block_removal_attempt
{
    meta:
        name = "S3 버킷 공개 접근 차단 설정 제거 시도"
        description = "Bucket public access block deletion attempted; includes approved changes and denied calls, other controls may still prevent public access"
        severity = "medium"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "s3.amazonaws.com"
        $name = event_name == "DeleteBucketPublicAccessBlock"
    condition:
        $src and $name
}

rule cloudtrail_snapshot_permission_change_attempt
{
    meta:
        name = "EC2 스냅샷 공유 권한 변경 시도"
        description = "Snapshot permission modification attempted; includes grants, revocations, dry runs and denied calls, not proof of public or external sharing"
        severity = "medium"
        log_type = "cloudtrail"
    fields:
        $src = event_source == "ec2.amazonaws.com"
        $name = event_name == "ModifySnapshotAttribute"
    condition:
        $src and $name
}
