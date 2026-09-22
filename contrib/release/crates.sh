#!/usr/bin/env bash
#
# Shared helpers for the release scripts. The workspace releases two crates:
# bitcoin-ohttp (member dir ohttp/) and bhttp (bhttp/), each released with
# its own <crate>-<version> tag.

# The crates these scripts release, in publish order.
RELEASED_CRATES="bitcoin-ohttp bhttp"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Succeed if $1 is a released crate.
is_released_crate() {
    case " $RELEASED_CRATES " in
        *" $1 "*) ;;
        *) return 1 ;;
    esac
}

# Print the workspace-relative manifest path of a released crate.
crate_manifest() {
    case "$1" in
        bitcoin-ohttp) printf 'ohttp/Cargo.toml' ;;
        bhttp) printf 'bhttp/Cargo.toml' ;;
        *) return 1 ;;
    esac
}

# Print the crate's manifest version.
manifest_version() {
    cargo metadata --no-deps --format-version 1 \
        --manifest-path "$REPO_ROOT/$(crate_manifest "$1")" |
        jq -r --arg c "$1" '.packages[] | select(.name == $c) | .version'
}

# Print the crate a <crate>-<version> release tag belongs to, or fail.
crate_from_tag() {
    for crate in $RELEASED_CRATES; do
        case "$1" in
            "$crate"-[0-9]*) printf '%s' "$crate"; return 0 ;;
        esac
    done
    return 1
}

# Print the version in a <crate>-<version> release tag, or fail.
version_from_tag() {
    crate="$(crate_from_tag "$1")" || return 1
    printf '%s' "${1#"${crate}"-}"
}

# Succeed if the version has a semver pre-release suffix.
is_prerelease() {
    case "$1" in
        *-*) return 0 ;;
        *) return 1 ;;
    esac
}

# Succeed if <version> of the crate exists on crates.io.
crate_published() {
    curl -sfL -o /dev/null -H "User-Agent: ohttp release tooling" \
        "https://crates.io/api/v1/crates/$1/$2"
}
