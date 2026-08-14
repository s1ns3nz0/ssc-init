#!/bin/sh
set -eu

usage() {
  echo "usage: scripts/generate-ti-key.sh [--private-output /absolute/private-key]" >&2
  exit 2
}

private_output=
if [ "$#" -eq 2 ] && [ "$1" = "--private-output" ]; then
  private_output=$2
elif [ "$#" -ne 0 ]; then
  usage
fi

case "$private_output" in
  "") ;;
  /*) ;;
  *) usage ;;
esac

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/ssc-init-ti-key.XXXXXX")
chmod 700 "$tmp_dir"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

private_tmp="$tmp_dir/private.pem"
public_tmp="$tmp_dir/public.pem"
openssl genpkey -algorithm ED25519 -out "$private_tmp" >/dev/null 2>&1
chmod 600 "$private_tmp"
openssl pkey -in "$private_tmp" -pubout -out "$public_tmp" >/dev/null 2>&1

public_der=$(openssl pkey -pubin -in "$public_tmp" -outform DER | tail -c 32 | base64 | tr -d '\n')
printf 'TI Ed25519 public key (base64 raw, commit only after review):\n%s\n' "$public_der"
printf 'Configure TI_KEY_ID as a reviewed repository variable.\n'
printf 'Store the raw 64-byte private key as TI_ED25519_PRIVATE_KEY using your secret manager/GitHub UI; never paste it into logs or source control.\n'

if [ -n "$private_output" ]; then
  parent=$(dirname "$private_output")
  [ -d "$parent" ] || { echo "private output parent does not exist" >&2; exit 1; }
  [ ! -e "$private_output" ] || { echo "private output already exists" >&2; exit 1; }
  seed=$(openssl pkey -in "$private_tmp" -outform DER | tail -c 32 | base64 | tr -d '\n')
  # Publisher accepts Go's raw 64-byte Ed25519 private key. Derive it without
  # ever placing the value on stdout.
  go run ./scripts/ti-key-expand.go "$seed" "$private_output"
  chmod 600 "$private_output"
  printf 'Private key written to the explicit path (mode 0600). Move it directly to the protected secret store.\n'
fi
