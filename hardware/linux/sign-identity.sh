#!/usr/bin/env bash
set -euo pipefail
umask 077
# Existing administrator-enrolled unrestricted RSA signing key only. No provisioning/eviction.
if [[ $# != 3 ]]; then echo 'usage: sign-identity.sh 0x810... challenge.txt NEW-output-directory' >&2; exit 2; fi
handle=$1; challenge=$2; output=$3
[[ $handle =~ ^0x81[0-9a-fA-F]{6}$ ]] || { echo 'Invalid persistent key handle' >&2; exit 2; }
[[ -f $challenge && $(wc -c < "$challenge") -le 4096 ]] || { echo 'Challenge size invalid' >&2; exit 2; }
command -v tpm2_sign >/dev/null; command -v tpm2_readpublic >/dev/null; command -v openssl >/dev/null
mkdir -- "$output"
head -c 4097 -- "$challenge" > "$output/challenge.txt"
challenge="$output/challenge.txt"
[[ $(wc -c < "$challenge") -le 4096 ]] || { echo 'Challenge size changed' >&2; exit 2; }
mapfile -t lines < "$challenge"
[[ ${#lines[@]} == 7 && ${lines[0]} == 'SENTRY-HARDWARE-IDENTITY-V2' && ${lines[1]} =~ ^session=[0-9a-f]{64}$ && ${lines[2]} =~ ^sequence=[1-9][0-9]{0,19}$ && ${lines[3]} =~ ^nonce=[0-9a-f]{64}$ && ${lines[4]} =~ ^instance=[A-Za-z0-9._-]{1,128}$ && ${lines[5]} =~ ^generation=[1-9][0-9]{0,19}$ && ${lines[6]} =~ ^policy=[A-Za-z0-9._-]{1,128}$ ]] || { echo 'Invalid domain-bound challenge' >&2; exit 2; }
[[ $(tail -c 1 "$challenge" | od -An -tu1 | tr -d ' ') == 10 ]] || { echo 'Final LF required' >&2; exit 2; }
tpm2_readpublic -c "$handle" -f pem -o "$output/public.pem" > "$output/provider-record.txt"
openssl dgst -sha256 -binary "$challenge" > "$output/challenge.digest"
tpm2_sign -c "$handle" -g sha256 -s rsassa -d -f plain -o "$output/signature.bin" "$output/challenge.digest"
openssl dgst -sha256 -verify "$output/public.pem" -signature "$output/signature.bin" "$challenge"
printf '%s\n' 'Recorded: identity signature only. Hardware provenance and platform state remain unverified.'
