# vrf
a VRF implementation in go (and JS just for verification part for now), following https://tools.ietf.org/html/draft-goldbe-vrf-00.

vrf_ed25519.go uses "golang.org/x/crypto/ed25519/internal/edwards25519" which is internal, so I copied the whole code into this repository as-is.
