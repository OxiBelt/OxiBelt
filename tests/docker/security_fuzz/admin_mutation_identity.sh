#!/usr/bin/env bash
# Source-only deterministic identity helper for valid Admin recovery mutations.

append_admin_identity_field() {
  local value="$1" length escaped
  local LC_ALL=C
  length="${#value}"
  printf -v escaped '\\x%02x\\x%02x\\x%02x\\x%02x' \
    "$((length >> 24 & 255))" "$((length >> 16 & 255))" \
    "$((length >> 8 & 255))" "$((length & 255))"
  printf '%b%s' "${escaped}" "${value}"
}

admin_valid_mutation_identity() {
  [[ "$#" == 8 ]] || {
    echo "Admin recovery identity requires eight context fields" >&2
    return 2
  }
  local phase="$1" target="$2" method="$3" path="$4" precondition="$5"
  local expected_previous_revision="$6" content_digest="$7" case_entropy="$8"
  local canonical_target identity_digest request_id new_revision field

  case "${phase}" in
    startup)
      [[ "${case_entropy}" == "startup" ]] || {
        echo "Admin startup recovery requires explicit startup entropy" >&2
        return 2
      }
      ;;
    post-case)
      [[ "${case_entropy}" =~ ^[0-9a-f]{64}$ ]] || {
        echo "Admin post-case recovery requires a canonical case seed" >&2
        return 2
      }
      ;;
    *)
      echo "unsupported Admin recovery identity phase" >&2
      return 2
      ;;
  esac
  [[ "${content_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "Admin recovery identity requires a canonical content digest" >&2
    return 2
  }
  canonical_target="$(jq -ceS \
    'if type == "object" then . else error("Admin mutation target must be an object") end' \
    <<<"${target}")"
  identity_digest="$({
    for field in \
      OXIBELT-SECURITY-FUZZ-ADMIN-IDENTITY 1 "${phase}" admin_authz \
      "${canonical_target}" "${method}" "${path}" "${precondition}" \
      "${expected_previous_revision}" "${content_digest}" "${case_entropy}"; do
      append_admin_identity_field "${field}"
    done
  } | sha256sum | awk 'NR == 1 {print $1}')"
  [[ "${identity_digest}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "failed to derive Admin recovery identity" >&2
    return 1
  }

  request_id="${identity_digest:0:8}-${identity_digest:8:4}-4${identity_digest:12:3}-8${identity_digest:15:3}-${identity_digest:18:12}"
  new_revision="sf-${identity_digest:32:32}"
  printf '%s\n%s\n' "${request_id}" "${new_revision}"
}
