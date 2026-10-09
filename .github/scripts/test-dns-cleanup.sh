#!/usr/bin/env bash
#
# Offline test for dns-cleanup.sh. It checks the V3 signer against the worked
# example in Alibaba Cloud's documentation, then runs the TXT cleanup against a
# local stand-in for the alidns API. The stand-in recomputes each signature
# from the request it receives and rejects mismatches.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dns-cleanup.sh
source "$here/dns-cleanup.sh"

work="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2> /dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

[[ "$(aliyun_urlencode 'a b*c~_.-')" == 'a%20b%2Ac~_.-' ]] || fail "percent-encoding"

signed="$(aliyun_v3_sign ecs.cn-shanghai.aliyuncs.com RunInstances 2014-05-26 \
  2023-10-26T10:22:32Z 3156853299f313e23d1673dc12e1703d YourAccessKeyId YourAccessKeySecret \
  ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd RegionId=cn-shanghai)"
[[ "$(sed -n 1p <<< "$signed")" == "ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai" ]] \
  || fail "canonical query of the documented example"
[[ "$(sed -n 2p <<< "$signed")" == *"Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0" ]] \
  || fail "signature of the documented example"

cat > "$work/alidns-stand-in.py" <<'PY'
import hashlib
import hmac
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, quote, unquote, urlsplit

PORT_FILE, CALLS_FILE, RECORDS_FILE, KEY_ID, SECRET = sys.argv[1:6]
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SIGNED_HEADERS = "host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version"


def signature_ok(handler):
    raw_query = urlsplit(handler.path).query
    pairs = [tuple(unquote(part) for part in item.split("=", 1)) for item in raw_query.split("&") if item]
    canonical_query = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in sorted(pairs))
    h = handler.headers
    headers = (
        f"host:{h.get('host', '')}\n"
        f"x-acs-action:{h.get('x-acs-action', '')}\n"
        f"x-acs-content-sha256:{h.get('x-acs-content-sha256', '')}\n"
        f"x-acs-date:{h.get('x-acs-date', '')}\n"
        f"x-acs-signature-nonce:{h.get('x-acs-signature-nonce', '')}\n"
        f"x-acs-version:{h.get('x-acs-version', '')}\n"
    )
    canonical_request = f"POST\n/\n{canonical_query}\n{headers}\n{SIGNED_HEADERS}\n{EMPTY_SHA256}"
    hashed = hashlib.sha256(canonical_request.encode()).hexdigest()
    string_to_sign = f"ACS3-HMAC-SHA256\n{hashed}"
    signature = hmac.new(SECRET.encode(), string_to_sign.encode(), hashlib.sha256).hexdigest()
    expected = f"ACS3-HMAC-SHA256 Credential={KEY_ID},SignedHeaders={SIGNED_HEADERS},Signature={signature}"
    ok = raw_query == canonical_query and h.get("authorization") == expected
    return ok and h.get("x-acs-content-sha256") == EMPTY_SHA256


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        ok = signature_ok(self)
        action = self.headers.get("x-acs-action", "")
        params = dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))
        with open(CALLS_FILE, "a") as calls:
            calls.write(json.dumps({"action": action, "params": params, "sig_ok": ok}) + "\n")
        if not ok:
            return self.reply(403, {"Code": "SignatureDoesNotMatch", "Message": "signature mismatch"})
        if action == "DescribeDomainRecords":
            with open(RECORDS_FILE) as records:
                records = json.load(records)
            return self.reply(200, {"TotalCount": len(records), "DomainRecords": {"Record": records}})
        if action == "DeleteDomainRecord":
            if params.get("RecordId") == "rec-gone":
                return self.reply(400, {"Code": "DomainRecordNotBelongToUser",
                                        "Message": "The DNS record does not exist in your account."})
            return self.reply(200, {"RecordId": params.get("RecordId"), "RequestId": "stand-in"})
        return self.reply(400, {"Code": "InvalidAction", "Message": action})

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(PORT_FILE, "w") as port_file:
    port_file.write(str(server.server_address[1]))
server.serve_forever()
PY

cat > "$work/records.json" <<'JSON'
[
  {"RecordId": "101", "RR": "_acme-challenge.run-111-1.ci-relay", "Type": "TXT", "Value": "a"},
  {"RecordId": "102", "RR": "_acme-challenge.run-222-1.ci-relay", "Type": "TXT", "Value": "b"},
  {"RecordId": "103", "RR": "_acme-challenge.run-111-1.ci-relay", "Type": "A", "Value": "192.0.2.1"},
  {"RecordId": "104", "RR": "@", "Type": "TXT", "Value": "apex"},
  {"RecordId": "105", "RR": "_acme-challenge.run-333-1.ci-relay", "Type": "TXT", "Value": "c"},
  {"RecordId": "106", "RR": "_acme-challenge.other.ci-relay", "Type": "TXT", "Value": "d"},
  {"RecordId": "rec-gone", "RR": "_acme-challenge.run-444-1.ci-relay", "Type": "TXT", "Value": "e"}
]
JSON

python3 "$work/alidns-stand-in.py" "$work/port" "$work/calls.jsonl" "$work/records.json" \
  LTAItest testsecret > "$work/stand-in.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
  if [[ -s "$work/port" ]]; then break; fi
  sleep 0.1
done
[[ -s "$work/port" ]] || fail "stand-in server did not start"

port="$(cat "$work/port")"
export CI_ALIYUN_ACCESS_KEY_ID=LTAItest
export CI_ALIYUN_ACCESS_KEY_SECRET=testsecret
export CI_ALIYUN_DOMAIN=example.com
export ALIYUN_DNS_BASE="http://127.0.0.1:$port"
unset CI_CF_TOKEN CI_CF_ZONE_ID

[[ "$(ci_dns_provider)" == aliyun ]] || fail "only Alibaba Cloud credentials should select aliyun"
(
  export CI_CF_TOKEN=token CI_CF_ZONE_ID=zone
  [[ "$(ci_dns_provider)" == cloudflare ]]
) || fail "Cloudflare credentials should win when both are set"

deleted_ids() {
  jq -r 'select(.action == "DeleteDomainRecord") | .params.RecordId' "$work/calls.jsonl" \
    | sort | tr '\n' ' '
}

delete_txt_records "run-111-1.ci-relay.example.com" "_acme-challenge." > "$work/run.out" 2>&1 \
  || fail "per-run cleanup must not fail"
[[ "$(deleted_ids)" == "101 " ]] || fail "per-run cleanup deleted [$(deleted_ids)]"

: > "$work/calls.jsonl"
delete_txt_records "ci-relay.example.com" "_acme-challenge.run-" > "$work/sweep.out" 2>&1 \
  || fail "startup sweep must not fail"
[[ "$(deleted_ids)" == "101 102 105 rec-gone " ]] || fail "startup sweep deleted [$(deleted_ids)]"
grep -q "could not delete TXT record rec-gone" "$work/sweep.out" \
  || fail "a record that is already gone should be reported, not fatal"

jq -e -s 'all(.[]; .sig_ok)' "$work/calls.jsonl" > /dev/null \
  || fail "the stand-in saw a request with a signature it could not verify"
jq -e -s 'any(.[]; .action == "DescribeDomainRecords" and .params.RRKeyWord == "_acme-challenge")' \
  "$work/calls.jsonl" > /dev/null || fail "record listing did not filter on _acme-challenge"

if CI_ALIYUN_ACCESS_KEY_SECRET=wrong-secret aliyun_api DescribeDomainRecords "DomainName=example.com" \
    > /dev/null 2> "$work/bad-secret.err"; then
  fail "a wrong AccessKey secret must be refused"
fi
grep -q "SignatureDoesNotMatch" "$work/bad-secret.err" || fail "refusal should name the error code"

(
  unset CI_ALIYUN_DOMAIN
  delete_txt_records "ci-relay.example.com" "_acme-challenge." > "$work/no-domain.out"
)
grep -q "CI_ALIYUN_DOMAIN is not set" "$work/no-domain.out" || fail "missing CI_ALIYUN_DOMAIN should be reported"

echo "dns-cleanup tests passed"
