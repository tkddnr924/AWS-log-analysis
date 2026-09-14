<h1 align="center">AWS Log Analyzer</h1>

<p align="center">
  S3 로 내려받은 AWS 로그를 그대로 읽는 분석기.<br />
  CloudTrail·ALB·WAF·API Gateway·nginx 를 한 케이스에 넣고, YARA 문법의 룰로 걸러 본다.
</p>

<p align="center">
  <a href="https://github.com/tkddnr924/AWS-log-analysis/releases"><img alt="release" src="https://img.shields.io/github/v/release/tkddnr924/AWS-log-analysis?style=flat-square" /></a>
  <img alt="platform" src="https://img.shields.io/badge/Windows-10%2F11%20x64-blue?style=flat-square" />
  <img alt="install" src="https://img.shields.io/badge/설치-불필요%20(단일%20exe)-brightgreen?style=flat-square" />
  <img alt="stack" src="https://img.shields.io/badge/Rust%20%2B%20Tauri%20%2B%20DuckDB-informational?style=flat-square" />
</p>

---

## 압축을 풀지 않는다

S3 에서 받은 폴더를 그대로 지정한다. 하위 폴더를 재귀로 훑어 `.gz` 파일을 모으고, 확장자가 아니라 **파일 앞부분을 열어 내용으로** 종류를 정한다. CloudTrail 객체처럼 gzip 멤버가 여러 개 이어 붙은 파일도 그대로 읽는다.

| 자동 판별 | 단서 |
|---|---|
| CloudTrail | `{"Records":[…]}` 와 `eventVersion`·`eventSource`·`eventTime` |
| ALB access log | 한 줄의 protocol · RFC 3339 시각 · `app/…` · client endpoint |
| WAF (`waf_acl`) | NDJSON 의 `webaclId`·`httpRequest`·`action` |
| API Gateway access log | NDJSON 의 `request_id`·`resource_path`·`http_method` |
| nginx (Elasticsearch export) | `_source` 아래 `event.dataset == "nginx.access"` |

CloudTrail digest 와 Config snapshot 은 알아보되 파싱 대상에서 뺀다. 파싱 전에 파일마다 대표 레코드 한 건을 보여 주므로 "이 데이터가 맞다"를 먼저 확인하고 시작한다. CloudTrail 은 정규화 필드와 원본 JSON 경로의 매핑을 화면에서 고칠 수 있다.

## YARA 문법으로 거른다

찾을 조건은 룰로 쓴다. 바이트 패턴 대신 **정규화된 필드**를 비교하므로 로그 종류가 달라도 같은 문법이다.

```yara
rule cloudtrail_console_login_failure
{
    meta:
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
```

| | |
|---|---|
| 공통 필드 | `event_time` `event_source` `event_name` `aws_region` `account_id` `source_ip` `user_agent` `error_code` |
| CloudTrail | `identity_type` `identity_arn` `identity_name` `mfa_authenticated` `read_only` `management_event` `resources[]` |
| 동적 경로 | `request.<k>` `response.<k>` — ALB 의 `response.elb_status_code`, WAF 의 `request.terminating_rule_id` 처럼 서비스별 속성 |
| 연산 | `== != > >= < <=` · `contains` `startswith` `endswith` (`i` 접두로 대소문자 무시) · `matches /regex/` · `in ("a", "b")` · `exists` `missing` |
| 조합 | `and` `or` `not` · 괄호 · `N of ($a, $b, …)` |

내장 룰 18개로 시작한다. CloudTrail 11개(루트 콘솔 로그인, 로그인 실패, MFA 없는 로그인, 권한 오류 반복, CloudTrail 로깅 중지, 긴 AssumeRole 세션, 루트 API 사용, IAM 정책 변경, 액세스 키 생성, KMS 키 비활성화, GuardDuty·Security Hub 비활성화), ALB 3개(5xx, 403, 프록시성 메서드), WAF 2개(차단, SQLi/XSS 룰셋 차단), API Gateway·nginx 5xx.

기본 룰 팩은 exe 안에 들어 있다. 어느 룰이든 원문을 열어 고쳐 저장하면 `cases/rules/` 의 사용자 룰이 되어 기본 룰을 덮고, 삭제하면 그 케이스에서만 빠진다. 룰은 파싱 때 평가하지 않는다 — 결과 화면에서 처음 고를 때 그 룰만 돌리므로, 3천만 건 케이스에서도 룰 하나가 20초 안팎이다.

## 결과를 다루는 방법

|  |  |
|---|---|
| **로그 타입 탭** | `전체` 와 케이스에 있는 타입별. 룰 목록·매치 수·이벤트 목록·검색이 전부 그 타입으로 좁혀진다 |
| **기간** | 룰보다 상위 조건. `2026-06-06`(그 날 전체) · `2026-06-06 11:00`(그 분 전체) · 초 단위까지, KST |
| **매치 목록** | 타입에 맞는 컬럼 — HTTP 는 메서드·상태·URL·대상, WAF 는 조치·국가·종료 룰, CloudTrail 은 이벤트·주체·리전·오류·리소스. 행을 고르면 정규화 필드와 원본 레코드 |
| **검색** | URL·IP·User-Agent·주체 통합 검색, 오래된순/최신순 |
| **룰 편집기** | 문법 오류 위치를 짚고, 저장 전에 케이스에 시험 실행해 몇 건이 걸리는지 보여 준다 |

## 시작하기

1. [Releases](https://github.com/tkddnr924/AWS-log-analysis/releases) 에서 `awslog-analysis.exe` 를 받는다.
2. 쓰기 가능한 폴더에 두고 실행한다. 설치도 관리자 권한도 필요 없다.
3. 로그 폴더를 고르고, 판별 결과를 확인한 뒤 **파싱 시작**을 누른다.

Windows 10 20H2 이상 / Windows 11 x64. 화면 표시에 쓰는 Edge WebView2 런타임은 해당 버전에 기본 포함되어 있고, Visual C++ 재배포 패키지는 필요 없다(CRT 정적 링크).

결과는 실행 파일 옆 `cases/` 에만 쌓인다. 케이스 하나가 폴더 하나(`session.duckdb` + 파싱 시점의 룰 스냅샷 + 로그)이며, 폴더째 복사하면 다른 PC 에서 그대로 열린다. AppData·레지스트리·시스템 temp 에는 아무것도 남기지 않으며, 네트워크로 나가는 것도 없다.

파싱은 파일 4개를 병렬로 스트리밍하고 메모리 사용량을 입력 크기와 무관하게 유지한다. 3.0 GB(2,572파일, 3,125만 건) ALB 로그 기준 약 6분, 최대 RSS 2.5 GB.
