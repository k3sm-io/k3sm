# Release index design

Status: accepted. The schema is implemented by `ParseReleaseIndex` in
`pkg/update/releaseindex.go`; its golden fixture and the host pin list live in
`pkg/update/testdata/release-index/`.

## Problem

The k3sm app updates itself and owns the version set: app vX bundles k3sm vX,
one tag, one sealed build tree, one tarball digest, one disk image. To tell a
user that a newer release exists, and to download it, the app needs one
document that names the latest final release and the exact bytes of both
halves of its set. That document has to be authentic (it decides what the app
offers to install), small, and strict, because it is read off the network.

## Scope

- The `k3sm-release-index/v1` document: its fields, their grammar and bounds.
- Its hosting as a release asset.
- The host pin list the app holds every download URL to.

Out of scope here: how the document is signed and verified (the app's release
step and verifier own that), how `publish.sh` uploads it, and the app's update
user interface.

## Threat model

The index is fetched over the network from a public release, and GitHub
redirects asset downloads to a CDN host. Neither the transport nor the host is
trusted: the index is CMS SignedData by the project's Developer ID Application
identity with a secure timestamp, and the app parses nothing until that
signature and its trust chain have been accepted. Parsing is still strict,
because a bug or a mistake in the release step must not turn into an offer to
install something else. Someone who can block or replay the fetch can keep the
app from learning about a newer release; they cannot make it install anything
the index does not name.

## The document

One JSON object, UTF-8, at most 64 KiB, checked before it is parsed. Exactly
one JSON value: anything after the object, a second value or stray bytes, is
refused. Every field is required. Keys are checked on the token stream before
the document is decoded, because common JSON decoders keep the last of two
equal keys and match keys without regard to case:

- every key is a schema key at its place, in exact case (`TAG` and `bundleId`
  are refused, not read as `tag` and `bundleID`);
- no key appears twice in one object, at any level;
- no value is an array.

So a v1 reader never silently ignores, or picks between, things a writer put
in the document. A key written with a JSON escape is compared after the escape
is decoded.

```json
{
  "schema": "k3sm-release-index/v1",
  "context": "io.k3sm.release-index/v1",
  "issuedAt": "2026-11-02T18:04:11Z",
  "tag": "v0.2.0",
  "minimumMacOS": "26.0",
  "app": {
    "bundleID": "io.k3sm.app",
    "shortVersion": "0.2.0",
    "image": {
      "name": "k3sm_0.2.0_darwin_arm64.dmg",
      "url": "https://github.com/k3sm-io/k3sm/releases/download/v0.2.0/k3sm_0.2.0_darwin_arm64.dmg",
      "sha256": "<64 lowercase hex>",
      "size": 123456789
    }
  },
  "k3sm": {
    "archive": "k3sm_0.2.0_darwin_arm64.tar.gz",
    "archiveSHA256": "<64 lowercase hex>",
    "payloadManifestSHA256": "<64 lowercase hex>"
  }
}
```

| field | grammar and bounds | read by |
|---|---|---|
| `schema` | exactly `k3sm-release-index/v1` | the decoder: a later format is a new string, never a reinterpretation |
| `context` | exactly `io.k3sm.release-index/v1` | the decoder: domain separation inside the signed content, so no other document the same identity signs reads as an index |
| `issuedAt` | `YYYY-MM-DDTHH:MM:SSZ`, UTC, whole seconds, a real date | the app's rollback check: an index with a lower tag, or the same tag and an older `issuedAt`, than one it accepted is refused |
| `tag` | a final release tag, `vMAJOR.MINOR.PATCH`, no leading zeros, no pre-release, no build metadata; also a valid git tag | the app's "up to date" and "update available" states, and the staged bundle's payload tag check |
| `minimumMacOS` | `MAJOR[.MINOR[.PATCH]]`, each part at most three digits | the app, before any download: a Mac below it is told so and nothing is fetched |
| `app.bundleID` | exactly `io.k3sm.app` | the staged bundle check |
| `app.shortVersion` | `tag` without its `v` | the app's update line, and the staged bundle's `CFBundleShortVersionString` check |
| `app.image.name` | exactly `k3sm_<version>_darwin_arm64.dmg`, `<version>` being `tag` without its `v` | the staged download's file name |
| `app.image.url` | exactly `https://github.com/k3sm-io/k3sm/releases/download/<tag>/<name>`, byte for byte: no port (not even `:443` or an empty one), no user information, no query or fragment, no other repository, tag or path | the download's first request |
| `app.image.sha256` | 64 lowercase hex | the downloaded image's digest check |
| `app.image.size` | 1 to 512 MiB | the download's byte cap and progress |
| `k3sm.archive` | exactly `k3sm_<version>_darwin_arm64.tar.gz` | the cross-check against the bundle's sealed release record |
| `k3sm.archiveSHA256` | 64 lowercase hex | the same cross-check: it must equal the tarball digest the app bundle seals |
| `k3sm.payloadManifestSHA256` | 64 lowercase hex | the same cross-check: the sha256 of the bundled tree's `PAYLOAD-SHA256` |

No field is carried without a reader. A release channel, the Kubernetes
version and a release notes link were considered and left out: there is one
channel (final releases), and nothing in the update path decides on the other
two.

### Final releases only

Only a final release publishes an index, and the decoder refuses a tag with a
pre-release or build suffix. A release candidate is never offered as an
update. An app built from a release candidate sees the latest final release as
older than itself and says so.

## Hosting

Two assets on the public `k3sm-io/k3sm` release, beside the disk image:
`k3sm_<version>_release-index.p7m` and the stable alias
`k3sm_release-index.p7m`, byte-identical. The app fetches the alias at

```
https://github.com/k3sm-io/k3sm/releases/latest/download/k3sm_release-index.p7m
```

The host carries no trust (the document is signed), only availability.

## The host pin list

`AllowedHosts` in `pkg/update/payload.go` is the one list of hosts a release
asset is fetched from, on the first request and on every redirect, for a
node's archive download and for the app alike. The URL an index names is
always on `github.com` (`ReleaseDownloadURL`); the other hosts in the list are
where GitHub redirects that request, so they are allowed for redirect hops and
never as the URL an index names. `pkg/update/testdata/release-index/allowed-hosts.json`
is that list exported as a JSON array; the test fails when the two differ. The
app's decoder test compares its own pin list against this fixture, so a host
added or removed here is a visible failure there until the app follows.

## The golden fixture

`index.json` is the canonical v1 document. The test decodes it and re-encodes
it to the same bytes, so a field added, dropped, renamed or reordered in the Go
type is a failing test until the fixture and this document change with it.
The app vendors the fixture byte for byte and decodes it with its own decoder.

Every `red-*.json` file is one change to the golden document that a decoder
must refuse: an unknown, case-variant or duplicate key at the top level and
nested, an array, a document that is not an object, trailing data, every field
outside its grammar, and every way the image URL can differ from the release
download URL (another host, a redirect host, another repository, another tag,
a `../` segment, an explicit port, a query, a fragment). The red files are the
refusal corpus the app's decoder runs too. They are generated from one table
in `pkg/update/releaseindex_test.go`; the test fails when a committed file is
not exactly its change to the golden or when a file is missing or stray, and
`go test ./pkg/update -run TestReleaseIndexSchemaGolden -update-release-index`
rewrites them. A document over the 64 KiB cap is built by the test rather than
committed.

## Decisions

- One document describes exactly one version set, the latest final release.
- The decoder runs only on content a signature check has accepted; it never
  verifies a signature itself.
- Strict decoding: unknown, case-variant and duplicate keys, trailing data
  and anything outside the grammar above are refused, never clipped into
  shape.
- The image URL is not a free field: it is the one release download URL its
  tag and name determine, so the tag in the path is bound to the index's tag.
- A change to the format is a new `schema` and `context` string, not an edit to
  v1.
