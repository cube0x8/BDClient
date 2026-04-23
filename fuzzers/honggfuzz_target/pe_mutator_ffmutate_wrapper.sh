#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PE_MUTATOR_REPO="${PE_MUTATOR_REPO:-../libafl-pe-mutator}"

if [[ -n "${PE_MUTATOR_CLI_BIN:-}" ]]; then
    :
else
    PE_MUTATOR_CLI_BIN="${PE_MUTATOR_REPO}/target/release/pe-mutator-cli"
fi

usage() {
    cat >&2 <<'EOF'
Usage:
  pe_mutator_ffmutate_wrapper.sh <input-path>

Environment:
  PE_MUTATOR_CLI_BIN           Override the pe-mutator-cli binary path
  PE_MUTATOR_REPO              Override the libafl-pe-mutator repository root
  PE_MUTATOR_REPORT_DIR        If set, write one mutation report per invocation
  PE_MUTATOR_WRAPPER_LOG       If set, append wrapper debug logs to this file
  PE_MUTATOR_SEED              Optional seed passed as --seed
  PE_MUTATOR_STACK_DEPTH       Optional fixed stack depth
  PE_MUTATOR_MIN_STACK_DEPTH   Optional minimum stack depth
  PE_MUTATOR_MAX_STACK_DEPTH   Optional maximum stack depth
  PE_MUTATOR_OVERLAY_MAX_LEN   Optional overlay max length
  PE_MUTATOR_ENABLE_BDENGINE_MUTATIONS
                               If set to 1, enable --enable-bdengine-mutations
EOF
}

log_wrapper() {
    if [[ -z "${PE_MUTATOR_WRAPPER_LOG:-}" ]]; then
        return
    fi

    mkdir -p -- "$(dirname -- "${PE_MUTATOR_WRAPPER_LOG}")"
    printf '[%s] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*" >> "${PE_MUTATOR_WRAPPER_LOG}"
}

if [[ $# -ne 1 ]]; then
    usage
    exit 2
fi

if [[ ! -x "${PE_MUTATOR_CLI_BIN}" ]]; then
    echo "pe-mutator-cli binary not found or not executable: ${PE_MUTATOR_CLI_BIN}" >&2
    echo "PE_MUTATOR_REPO: ${PE_MUTATOR_REPO}" >&2
    echo "Build it first with: cargo build -p pe-mutator-cli" >&2
    exit 1
fi

input_path="$1"

# honggfuzz may pass seeds from corpus/dynamic corpus that are not valid PEs yet.
# For ffmutate_cmd this should be a no-op, not a fatal error.
if [[ ! -r "${input_path}" ]]; then
    log_wrapper "input=${input_path} readable=0"
    echo "input file is not readable: ${input_path}" >&2
    exit 1
fi

input_size="$(wc -c < "${input_path}")"
input_magic="$(head -c 2 "${input_path}" 2>/dev/null || true)"
log_wrapper "input=${input_path} size=${input_size} magic=$(printf '%q' "${input_magic}")"

if [[ "${input_size}" -lt 64 ]]; then
    log_wrapper "input=${input_path} action=skip reason=size_lt_64"
    exit 0
fi

if [[ "${input_magic}" != "MZ" ]]; then
    log_wrapper "input=${input_path} action=skip reason=magic_not_mz"
    exit 0
fi

cmd=( "${PE_MUTATOR_CLI_BIN}" mutate "${input_path}" )
report_path=""

if [[ -n "${PE_MUTATOR_REPORT_DIR:-}" ]]; then
    mkdir -p -- "${PE_MUTATOR_REPORT_DIR}"
    report_name="pe-mutator.$$.${RANDOM}.$(date +%s%N).report.txt"
    report_path="${PE_MUTATOR_REPORT_DIR}/${report_name}"
    cmd+=( --report "${report_path}" )
fi

if [[ -n "${PE_MUTATOR_SEED:-}" ]]; then
    cmd+=( --seed "${PE_MUTATOR_SEED}" )
fi

if [[ -n "${PE_MUTATOR_STACK_DEPTH:-}" ]]; then
    cmd+=( --stack-depth "${PE_MUTATOR_STACK_DEPTH}" )
fi

if [[ -n "${PE_MUTATOR_MIN_STACK_DEPTH:-}" ]]; then
    cmd+=( --min-stack-depth "${PE_MUTATOR_MIN_STACK_DEPTH}" )
fi

if [[ -n "${PE_MUTATOR_MAX_STACK_DEPTH:-}" ]]; then
    cmd+=( --max-stack-depth "${PE_MUTATOR_MAX_STACK_DEPTH}" )
fi

if [[ -n "${PE_MUTATOR_OVERLAY_MAX_LEN:-}" ]]; then
    cmd+=( --overlay-max-len "${PE_MUTATOR_OVERLAY_MAX_LEN}" )
fi

if [[ "${PE_MUTATOR_ENABLE_BDENGINE_MUTATIONS:-0}" == "1" ]]; then
    cmd+=( --enable-bdengine-mutations )
fi

if ! "${cmd[@]}"; then
    # Parsing/compatibility failures on non-parseable inputs must not abort honggfuzz.
    log_wrapper "input=${input_path} action=mutate_failed report=${report_path:-none}"
    exit 0
fi

output_size="$(wc -c < "${input_path}")"
output_magic="$(head -c 2 "${input_path}" 2>/dev/null || true)"
log_wrapper "input=${input_path} action=mutated output_size=${output_size} output_magic=$(printf '%q' "${output_magic}") report=${report_path:-none}"
