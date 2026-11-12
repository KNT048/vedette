# Patched go.mod / go.sum of nuclei (D-319)

The `scan-base` image does not ship the upstream nuclei release binary. It builds nuclei from the source archive of the tag pinned in
`../../pins.env` (`NUCLEI_VERSION`, `NUCLEI_SRC_SHA256`) with the pinned Go (`GOLANG_IMAGE`) and these two files copied over the
upstream `go.mod` and `go.sum`, so the standard library and the Go modules inside the binary carry the security fixes upstream has not
released yet. `go.sum` verifies every module the build downloads. Only the versions of dependencies differ from upstream's files.

Made for nuclei 3.11.1 with Go 1.26.11, from the unpacked archive:

    GOTOOLCHAIN=local GOFLAGS=-mod=mod go get \
      github.com/getkin/kin-openapi@v0.149.0 github.com/go-git/go-git/v5@v5.19.2 github.com/go-jose/go-jose/v4@v4.1.6 \
      golang.org/x/crypto@v0.58.0 golang.org/x/mod@v0.41.0 golang.org/x/net@v0.62.0 golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.83.2
    GOTOOLCHAIN=local GOFLAGS=-mod=mod go mod tidy

then copy `go.mod` and `go.sum` here. (x/crypto, x/mod and x/text are above the fixed versions only because x/net 0.62.0 requires them.)

Redo this on EVERY change of `NUCLEI_VERSION` or `GOLANG_IMAGE`: unpack the new archive, run `trivy rootfs` on a build, raise every module it
reports to its fixed version with `go get`, `go mod tidy`, copy the two files, `make images-check`, `make vuln-scan`. When upstream's own
`go.mod` already carries the fixed versions, delete this folder and build with the archive's files.
