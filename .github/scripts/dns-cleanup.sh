#!/usr/bin/env bash
#
# Removes ACME DNS-01 TXT records left behind by the integration test. Sourced
# by integration-test.sh and test-dns-cleanup.sh; it does not run on its own.
#
# The provider follows the relay's rule: Alibaba Cloud DNS when only its
# credentials are set, Cloudflare otherwise.

ALIYUN_EMPTY_BODY_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ALIYUN_API_VERSION="2015-01-09"

# Prints the DNS provider the relay will use for the CI_* credentials.
ci_dns_provider() {
  local has_cloudflare=0 has_aliyun=0
  if [ -n "${CI_CF_TOKEN:-}" ] || [ -n "${CI_CF_ZONE_ID:-}" ]; then
    has_cloudflare=1
  fi
  if [ -n "${CI_ALIYUN_ACCESS_KEY_ID:-}" ] || [ -n "${CI_ALIYUN_ACCESS_KEY_SECRET:-}" ]; then
    has_aliyun=1
  fi
  if [ "$has_aliyun" = 1 ] && [ "$has_cloudflare" = 0 ]; then
    echo aliyun
  else
    echo cloudflare
  fi
}

# Deletes Cloudflare TXT records whose names start with $2 and end with $1.
# Cloudflare applies the suffix filter. Failures are reported, never fatal.
cloudflare_delete_txt_records() {
  local suffix="$1" prefix="$2"
  local api="https://api.cloudflare.com/client/v4/zones/${CI_CF_ZONE_ID}/dns_records"
  local ids id
  if ! ids=$(curl -fsS -H "Authorization: Bearer ${CI_CF_TOKEN}" \
      "${api}?type=TXT&per_page=100&name.endswith=${suffix}" \
      | jq -r --arg prefix "$prefix" \
        '.result[] | select(.name | startswith($prefix)) | .id'); then
    echo "could not list TXT records ending in ${suffix}"
    return 0
  fi
  for id in $ids; do
    if curl -fsS -X DELETE -H "Authorization: Bearer ${CI_CF_TOKEN}" \
        "${api}/${id}" > /dev/null; then
      echo "deleted TXT record ${id}"
    else
      echo "could not delete TXT record ${id}"
    fi
  done
}

# RFC 3986 percent-encoding, as Alibaba Cloud requires for signed parameters.
aliyun_urlencode() {
  local LC_ALL=C input="$1" out="" i char hex
  for ((i = 0; i < ${#input}; i++)); do
    char="${input:i:1}"
    case "$char" in
      [a-zA-Z0-9._~-]) out+="$char" ;;
      *)
        printf -v hex '%%%02X' "'$char"
        out+="$hex"
        ;;
    esac
  done
  printf '%s' "$out"
}

# Signs a DNS API call with Alibaba Cloud's V3 scheme (ACS3-HMAC-SHA256).
# Arguments: host, action, API version, UTC date, nonce, AccessKey ID,
# AccessKey secret, then the parameters as name=value. Prints the canonical
# query string on the first line and the Authorization header value on the
# second.
aliyun_v3_sign() {
  local host="$1" action="$2" version="$3" date="$4" nonce="$5"
  local key_id="$6" secret="$7"
  shift 7
  local signed_headers="host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"
  local query="" pair canonical_headers canonical_request hashed string_to_sign signature
  while IFS= read -r pair; do
    query+="${query:+&}$(aliyun_urlencode "${pair%%=*}")=$(aliyun_urlencode "${pair#*=}")"
  done < <(printf '%s\n' "$@" | LC_ALL=C sort -t= -k1,1)
  printf -v canonical_headers 'host:%s\nx-acs-action:%s\nx-acs-content-sha256:%s\nx-acs-date:%s\nx-acs-signature-nonce:%s\nx-acs-version:%s' \
    "$host" "$action" "$ALIYUN_EMPTY_BODY_SHA256" "$date" "$nonce" "$version"
  printf -v canonical_request 'POST\n/\n%s\n%s\n\n%s\n%s' \
    "$query" "$canonical_headers" "$signed_headers" "$ALIYUN_EMPTY_BODY_SHA256"
  hashed="$(printf '%s' "$canonical_request" | openssl dgst -sha256 -hex | awk '{print $NF}')"
  printf -v string_to_sign 'ACS3-HMAC-SHA256\n%s' "$hashed"
  signature="$(printf '%s' "$string_to_sign" | openssl dgst -sha256 -hmac "$secret" -hex | awk '{print $NF}')"
  printf '%s\nACS3-HMAC-SHA256 Credential=%s,SignedHeaders=%s,Signature=%s\n' \
    "$query" "$key_id" "$signed_headers" "$signature"
}

# Calls one Alibaba Cloud DNS action with the parameters given as name=value
# and prints the JSON response. On an error, prints the error code and message
# to stderr and returns non-zero.
aliyun_api() {
  local action="$1"
  shift
  local base="${ALIYUN_DNS_BASE:-https://alidns.aliyuncs.com}"
  local host="${base#*://}"
  host="${host%%/*}"
  local date nonce query authorization response status
  date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  nonce="$(openssl rand -hex 16)"
  { IFS= read -r query && IFS= read -r authorization; } < <(
    aliyun_v3_sign "$host" "$action" "$ALIYUN_API_VERSION" "$date" "$nonce" \
      "$CI_ALIYUN_ACCESS_KEY_ID" "$CI_ALIYUN_ACCESS_KEY_SECRET" "$@" "Lang=en"
  )
  response="$(mktemp)"
  status="$(curl -sS -g -o "$response" -w '%{http_code}' -X POST \
    -H "authorization: ${authorization}" \
    -H "accept: application/json" \
    -H "x-acs-action: ${action}" \
    -H "x-acs-version: ${ALIYUN_API_VERSION}" \
    -H "x-acs-date: ${date}" \
    -H "x-acs-signature-nonce: ${nonce}" \
    -H "x-acs-content-sha256: ${ALIYUN_EMPTY_BODY_SHA256}" \
    "${base}/?${query}")" || status=000
  if [ "${status:0:1}" = 2 ]; then
    cat "$response"
    rm -f "$response"
    return 0
  fi
  echo "Alibaba Cloud DNS ${action} failed (HTTP ${status}): $(jq -r '(.Code // "no error code") + ": " + (.Message // "")' "$response" 2> /dev/null || echo "unreadable response")" >&2
  rm -f "$response"
  return 1
}

# Deletes Alibaba Cloud TXT records in zone $1 whose full names start with $3
# and end with $2. Failures are reported, never fatal.
aliyun_delete_txt_records() {
  local zone="$1" suffix="$2" prefix="$3"
  local body ids id
  if ! body=$(aliyun_api DescribeDomainRecords "DomainName=${zone}" \
      "RRKeyWord=_acme-challenge" "TypeKeyWord=TXT" "PageSize=500"); then
    echo "could not list TXT records in ${zone}"
    return 0
  fi
  if ! ids=$(jq -r --arg zone "$zone" --arg prefix "$prefix" --arg suffix "$suffix" '
      .DomainRecords.Record[]?
      | select(.Type == "TXT")
      | (if (.RR // "") == "@" then $zone else (.RR // "") + "." + $zone end) as $name
      | select($name | startswith($prefix) and endswith($suffix))
      | .RecordId' <<< "$body"); then
    echo "could not read the record list for ${zone}"
    return 0
  fi
  for id in $ids; do
    if aliyun_api DeleteDomainRecord "RecordId=${id}" > /dev/null; then
      echo "deleted TXT record ${id}"
    else
      echo "could not delete TXT record ${id}"
    fi
  done
}

# Deletes TXT records whose names start with $2 and end with $1, through the
# provider the relay uses. Failures are reported, never fatal.
delete_txt_records() {
  local suffix="$1" prefix="$2"
  case "$(ci_dns_provider)" in
    aliyun)
      if [ -z "${CI_ALIYUN_DOMAIN:-}" ]; then
        echo "CI_ALIYUN_DOMAIN is not set; TXT records cannot be removed"
        return 0
      fi
      aliyun_delete_txt_records "$CI_ALIYUN_DOMAIN" "$suffix" "$prefix"
      ;;
    *)
      if [ -z "${CI_CF_TOKEN:-}" ] || [ -z "${CI_CF_ZONE_ID:-}" ]; then
        return 0
      fi
      cloudflare_delete_txt_records "$suffix" "$prefix"
      ;;
  esac
}
