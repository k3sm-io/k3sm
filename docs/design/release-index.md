# Release index design

Status: accepted. Both documents are implemented in
`pkg/update/releaseindex.go`: `ParseReleaseIndex` decodes the stable document,
and `ParseCandidateIndex` decodes the candidate document. The stable golden
fixture and the host pin list live in `pkg/update/testdata/release-index/`, and
the candidate corpus in `pkg/update/testdata/release-index-rc/`.

## Problem

The k3sm app owns the version set: app vX bundles k3sm vX,
one tag, one sealed build tree, one tarball digest, one disk image. In v0.2 the app does not check for a new release; that check
arrives in v0.3, and installing a release in place comes after it. To tell a
user that a newer release exists, and to download it, the app needs one
document that names the latest final release and the exact bytes of both
halves of its set. That document has to be authentic (it decides what the app
offers to install), small, and strict, because it is read off the network.

## Scope

- The `k3sm-release-index/v1` document: its fields, their grammar and bounds.
- The `k3sm-release-index-rc/v1` document, a release candidate's sibling of it.
- Their hosting as release assets.
- The host pin list the app holds every download URL to.

Out of scope here: how a document is signed and verified (the app's release
step and verifier own that), how `publish.sh` uploads it, how a candidate is
discovered, and the app's update user interface.

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
  "minimumSupportedTag": "v0.1.0",
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
| `minimumSupportedTag` | a final release tag with the grammar of `tag`, at or below `tag` | the app's go-back: it refuses to go back to a release below it. A later index can raise it after a bad release ships, and a record kept on the Mac cannot lower it |
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
version and a release notes link were considered and left out: this document
only ever names a final release, and nothing in the update path decides on the
other two.

### Final releases only

This document names a final release, and its decoder refuses a tag with a
pre-release or build suffix. A stable reader is never offered a release
candidate. An app built from a release candidate sees the latest final release
as older than itself and says so.

## The candidate document

A release candidate publishes its own document, `k3sm-release-index-rc/v1`,
with one document for each candidate release. It is a sibling of the stable
document and not a version of it: the key tree, the size cap and the strict key
checks are the same, one decoder takes both, and the caller says which it
expects, with no default. These fields differ:

| field | candidate document |
|---|---|
| `schema` | exactly `k3sm-release-index-rc/v1` |
| `context` | exactly `io.k3sm.release-index-rc/v1` |
| `tag` | a release candidate tag, `vMAJOR.MINOR.PATCH-rc.N`, `N` at most four digits, no leading zeros; a final tag is refused |
| `app.shortVersion` | the `X.Y.Z` core of `tag`, the only form `CFBundleShortVersionString` takes |
| `app.image.name` | exactly `k3sm_<version>_darwin_arm64.dmg`, `<version>` being `tag` without its `v`, so it carries `-rc.N` |
| `app.image.url` | exactly `https://github.com/k3sm-io/k3sm/releases/download/<tag>/<name>`, as on the stable document |
| `k3sm.archive` | exactly `k3sm_<version>_darwin_arm64.tar.gz`, likewise carrying `-rc.N` |
| `minimumSupportedTag` | a final release tag at or below `tag`, so a candidate's own final is too high |

The schema and context strings keep the two apart in the signed content: a
signature over a candidate document never reads as a stable index, and the
reverse. Each decoder refuses the other's document, so an older app, which holds
only the stable decoder, refuses a candidate document by its schema string.

A candidate document is read at a tag: `ParseCandidateIndex` takes the tag the
reader asked for and refuses a document naming any other, however valid. So a
document signed for one candidate cannot be replayed at another's path to hold a
reader on an older candidate, or to offer it one it did not ask for.

## Hosting

Two assets on the public `k3sm-io/k3sm` release, beside the disk image:
`k3sm_<version>_release-index.p7m` and the stable alias
`k3sm_release-index.p7m`, byte-identical. The app fetches the alias at

```
https://github.com/k3sm-io/k3sm/releases/latest/download/k3sm_release-index.p7m
```

The host carries no trust (the document is signed), only availability.

A release candidate carries one asset, `k3sm_<version>_release-index.p7m`, and no
alias: it is never the release marked latest, so `releases/latest/download/`
never reaches it, and a stable reader must never meet its document. A reader
fetches it by tag:

```
https://github.com/k3sm-io/k3sm/releases/download/<tag>/k3sm_<version>_release-index.p7m
```

A candidate published with no document is not an error for a reader. It means
the app has nothing to offer at that tag.

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

### The candidate corpus

`pkg/update/testdata/release-index-rc/` is the contract the app's candidate
decoder reads: this path and these rules, with no other agreement between the
two repositories.

- `index.json` is the canonical candidate document, for the tag `v0.3.0-rc.2`.
  It must decode at that tag and re-encode to the same bytes.
- Every `red-*.json` file must be refused when read as the candidate document
  at `v0.3.0-rc.2`. That one rule covers all of them, including
  `red-replayed-older-candidate.json` and `red-replayed-newer-candidate.json`,
  which are valid documents for another candidate and are refused only because
  of the tag they were read at, and `red-stable-document.json`, which is the
  stable golden byte for byte.
- A reader of the stable document must refuse `index.json` here, and a reader of
  the candidate document must refuse `index.json` in the stable directory.

The files are generated from one table in
`pkg/update/candidateindex_test.go`, the test fails when a committed file is not
exactly its change to the golden or when a file is missing or stray, and
`go test ./pkg/update -run TestCandidateIndexSchemaGolden -update-release-index`
rewrites them. The same test pins the bytes of the stable golden.

## Decisions

- One document describes exactly one version set: the stable document the
  latest final release, the candidate document its own candidate.
- A candidate's document is a sibling with its own strings, not a `v2` with a
  channel field. A `v2` would make finals publish two documents, or readers
  migrate at once, for no reader that v1 does not already serve.
- The decoder runs only on content a signature check has accepted; it never
  verifies a signature itself.
- Strict decoding: unknown, case-variant and duplicate keys, trailing data
  and anything outside the grammar above are refused, never clipped into
  shape.
- The image URL is not a free field: it is the one release download URL its
  tag and name determine, so the tag in the path is bound to the index's tag.
- A change to the format is a new `schema` and `context` string, not an edit to
  v1. `minimumSupportedTag` was added to v1 before any index was published, so
  no reader of the older shape exists. From the first published index on, the
  rule holds as written.
