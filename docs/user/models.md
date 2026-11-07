# Models in the cluster registry

k3sm stores a model as a [ModelPack](https://github.com/modelpack/model-spec) OCI artifact in the cluster
registry, under `registry-k3sm:6450/models/<name>`. You put a model there once, from your Mac, and every
node pulls it from the cluster. No pod needs internet access to get its weights.

Three verbs manage these artifacts:

| Verb | What it does |
|---|---|
| `k3sm model push <dir> <name>[:tag]` | Builds an artifact from the files in a directory and pushes it. |
| `k3sm model import hf://<org>/<repo>[@<revision>] [<name>[:tag]]` | Imports a Hugging Face repository at a pinned commit and pushes it. |
| `k3sm model rm <name>[:tag]` | Removes a tag. |

The tag defaults to `latest`. Each verb that writes prints the manifest digest and a `models/<name>@sha256:…`
reference you can pin.

## The Artifact Layout

Each file becomes one raw, uncompressed layer, and the layer records the file's path. The weights must be
safetensors or GGUF, but not both. A split set (`model-0000N-of-0000M.safetensors` with its
`model.safetensors.index.json`, or `-0000N-of-0000M.gguf`) is one artifact with one layer per split, and a set
with a split missing is refused. The manifest is deterministic: layers are sorted by path and carry no
timestamps, so the same files always give the same digest.

Some files are refused by name before any file is read:

- code and pickle files: `.py`, `.pyc`, `.bin`, `.pt`, `.pth`, `.pkl`, `.pickle`, `.ckpt`, `.so`, `.dylib`;
- symbolic links;
- paths with bytes outside `[A-Za-z0-9._-/]`;
- paths that collide when case is ignored.

A repository that ships `pytorch_model.bin` next to its safetensors is refused as a whole. Copy the files you
want into a directory and use `model push` instead.

## Push a Directory

```sh
k3sm model push ./Qwen3-0.6B-4bit qwen3-0.6b:4bit
```

A push writes the way `k3sm image push` does. It uses the server's push credential when your account can read
it, and otherwise a builder token through your kubeconfig. A blob the registry already holds is not uploaded
again. When the tag already names the same manifest, nothing is uploaded at all.

## Import From Hugging Face

```sh
k3sm model import hf://mlx-community/Qwen3-0.6B-4bit@main
```

This pushes `models/mlx-community/qwen3-0.6b-4bit:latest`. Give a second argument to choose the name and tag:

```sh
k3sm model import hf://mlx-community/Qwen3-0.6B-4bit@main qwen3-0.6b:4bit
```

The import runs on your Mac, not in a pod, and only that Mac needs internet access. It works in this order:

1. **The revision is pinned.** A branch or tag (the default is `main`) is resolved to its 40-hex commit.
   Every file is then fetched at that commit, so a branch that moves during the import changes nothing. The
   manifest records the commit in `org.opencontainers.image.revision` and the source in
   `org.opencontainers.image.source` (`hf://<org>/<repo>`).
2. **Every name is checked before anything is downloaded**, with the same rules `model push` uses.
3. **Every file is downloaded and verified before anything is pushed.** An LFS file must match the sha256 the
   Hub lists for it, and that sha256 becomes its layer digest. A small file must match its git blob id. If
   one byte is wrong, the import stops and pushes nothing. A transfer that breaks is resumed with a range
   request, up to five attempts per file.
4. **The artifact is pushed** the way `model push` pushes it.

Run the same import again and it uploads nothing and prints the same digest.

Files are downloaded into a new `k3sm-hf-import-*` subdirectory of the system temporary directory, and the
import prints its path. The directory is removed when the import ends, including when Ctrl-C stops it. If the
process is killed outright, the directory stays behind. The next import removes any of your
`k3sm-hf-import-*` directories in the same parent in which nothing has changed for 24 hours, and says so. Before the first download, the import checks that the directory's volume has room for the
whole model plus a reserve of 5% (at least 1 GiB). If it does not, the import stops before fetching
anything. Choose another parent with `--scratch-dir <dir>`.

### What the Import Trusts

The import trusts the Hub the first time it sees a model. The Hub's hashes catch corruption in transit, but
they cannot catch a compromised Hub or repository. If you know a file's sha256 from somewhere else, pass it,
and it is checked as well:

```sh
k3sm model import --sha256 model.safetensors=<64 hex digits> hf://<org>/<repo>@<commit>
```

Pass `--sha256` once for each file you want to check.

Downloads use https only. Redirects are followed only to the Hub's own host and its published CDN hosts.

### What the Import Refuses

- **Gated repositories.** The import is anonymous and never sends a token. A repository that asks you to
  accept terms is refused by name. Download it yourself after accepting the terms, then use `model push`.
- **Private or missing repositories**, which the Hub does not show to an anonymous caller.
- **Anything it does not recognise.** This includes an unknown entry type in the file listing, a hash in an
  unknown form, a header that contradicts the listing, and an unexpected status.
- **Repositories over its size limits:**

| Limit | Value |
|---|---|
| File listing | 16 MiB, 100,000 entries, 128 pages |
| Files in one model | 4096 |
| One LFS file | 256 GiB |
| One small (non-LFS) file | 64 MiB |
| The whole repository | 1 TiB |
| Redirects per request | 5 |

## Remove a Tag

```sh
k3sm model rm qwen3-0.6b:4bit
```

`rm` removes a name, not bytes. The registry reclaims content that no tag names at its next garbage
collection. It needs the server's push credential, so run it on the server as root, because the push gate
never forwards a delete.
