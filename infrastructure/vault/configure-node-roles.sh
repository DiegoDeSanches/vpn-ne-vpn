#!/bin/sh
set -eu

usage() {
  echo "usage: $0 CLOUD NODE_ID WORKLOAD_IDENTITY APP_POLICY_TEMPLATE ONION_POLICY_TEMPLATE [GCP_PROJECT]" >&2
  exit 64
}

[ "$#" -ge 5 ] && [ "$#" -le 6 ] || usage
cloud=$1
node_id=$2
workload_identity=$3
app_template=$4
onion_template=$5
gcp_project=${6:-}

: "${VAULT_ADDR:?set the HTTPS Vault endpoint}"
case "$VAULT_ADDR" in https://*) ;; *) exit 64 ;; esac
case "$node_id" in ''|*[!a-z0-9-]*) exit 64 ;; esac
[ "${#node_id}" -le 40 ] || exit 64
case "$workload_identity" in ''|*[!0-9A-Za-z:/.@_+=,-]*) exit 64 ;; esac
[ "${#workload_identity}" -le 512 ] || exit 64
[ -f "$app_template" ] && [ -f "$onion_template" ] || exit 66
command -v vault >/dev/null 2>&1 || exit 69

scope="kv/data/nodes/$node_id"
app_policy="node-$node_id-app"
onion_policy="node-$node_id-onion"
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT INT TERM

render_policy() {
  source_file=$1
  destination=$2
  grep -q 'NODE_SCOPE' "$source_file" || exit 64
  sed "s|NODE_SCOPE|$scope|g" "$source_file" > "$destination"
  if grep -q 'NODE_SCOPE' "$destination"; then
    exit 64
  fi
}

render_policy "$app_template" "$temp_dir/app.hcl"
render_policy "$onion_template" "$temp_dir/onion.hcl"
vault policy write "$app_policy" "$temp_dir/app.hcl" >/dev/null
vault policy write "$onion_policy" "$temp_dir/onion.hcl" >/dev/null

write_aws_role() {
  role_name=$1
  policy_name=$2
  vault write "auth/aws/role/$role_name" \
    auth_type=iam \
    "bound_iam_principal_arn=$workload_identity" \
    "policies=$policy_name" \
    ttl=2m max_ttl=2m token_type=batch token_no_default_policy=true >/dev/null
}

write_gcp_role() {
  role_name=$1
  policy_name=$2
  vault write "auth/gcp/role/$role_name" \
    type=gce \
    "project_id=$gcp_project" \
    "bound_service_accounts=$workload_identity" \
    "policies=$policy_name" \
    ttl=2m max_ttl=2m token_type=batch token_no_default_policy=true >/dev/null
}

case "$cloud" in
  aws)
    [ "$#" -eq 5 ] || usage
    case "$workload_identity" in arn:aws:iam::*:role/*) ;; *) exit 64 ;; esac
    write_aws_role "$node_id" "$app_policy"
    write_aws_role "$node_id-onion" "$onion_policy"
    ;;
  gcp)
    [ "$#" -eq 6 ] || usage
    case "$gcp_project" in ''|*[!a-z0-9-]*) exit 64 ;; esac
    case "$workload_identity" in *@"$gcp_project".iam.gserviceaccount.com) ;; *) exit 64 ;; esac
    write_gcp_role "$node_id" "$app_policy"
    write_gcp_role "$node_id-onion" "$onion_policy"
    ;;
  *) usage ;;
esac

