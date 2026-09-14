export function formatBytes(bytes: number) {
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

/** Log types the backend can parse, in tab order (docs/03). */
export const PARSEABLE_LOG_TYPES = [
  "cloudtrail",
  "alb_access",
  "waf_acl",
  "apigw_access",
  "nginx_access",
] as const;

export function isParseableLogType(logType: string) {
  return (PARSEABLE_LOG_TYPES as readonly string[]).includes(logType);
}

/** Analyst-facing name of a `files.log_type` value. */
export function logTypeLabel(logType: string) {
  switch (logType) {
    case "cloudtrail":
      return "CloudTrail";
    case "alb_access":
      return "ALB";
    case "waf_acl":
      return "WAF";
    case "apigw_access":
      return "API Gateway";
    case "nginx_access":
      return "nginx";
    case "cloudtrail_digest":
      return "Digest";
    case "config_snapshot":
      return "Config";
    default:
      return "판별 안 됨";
  }
}
