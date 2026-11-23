# Sample apps for testing Guardian on more ecosystems (SIMULATED)

Small, synthetic projects, one per ecosystem, that plant known supply-chain risks. They exist so Guardian's
detectors can be tested on JavaScript, Python, Go, Java (Gradle and Maven) and C/C++ with an exact ground truth,
offline. Real projects are tested too: see `testbed/corpus.yaml` and `docs/TESTING.md`.

* **Never built, installed or run.** They are text fixtures. Guardian reads them statically; the tools that read
  them (Syft, Grype, zizmor, npm resolution) run in the podman sandbox (`guardian/sandbox`, `docs/SETUP.md`).
* Every URL that looks risky points at `example.com`, `example.invalid` or a private address. Nothing here is a
  real attack payload.
* `expected.json` is the ground truth: which findings and components each app must produce. It was written from
  what was planted, not copied from Guardian's output. `tests/test_sample_apps.py` checks it.
* `cpp-pinned` and `go-pinned` are **controls**: everything pinned and verified, so they must produce no findings
  (false-positive check).

| App | Ecosystem | Planted risks |
|---|---|---|
| `js-web` | npm + HTML | look-alike `lodahs` from an unapproved host with an install script; CDN script without SRI |
| `python-api` | pip | `--extra-index-url` (dependency confusion), `--trusted-host`, an import not declared anywhere |
| `go-service` | Go modules | `replace` to a fork, no `go.sum`, `GOFLAGS=-insecure` and `GONOSUMDB` in the Makefile |
| `java-gradle` | Gradle | plain-HTTP repository, extra repository (jitpack), `31.+` dynamic version, wrapper without checksum |
| `java-maven` | Maven | plain-HTTP repository, version range, Maven wrapper without checksum |
| `cpp-native` | CMake, vcpkg, conan, meson, submodules | FetchContent at `master`, unverified HTTP download, vcpkg without baseline, conan range without lockfile, `git://` submodule, meson wrap at `HEAD` |
| `cpp-pinned` | same, all pinned | control: 0 findings |
| `go-pinned` | Go modules | control: 0 findings |

Scan one yourself (it must be a git repository; copy it out first):

```bash
cp -r testbed/apps/java-gradle /tmp/jg && git -C /tmp/jg init -q && git -C /tmp/jg add -A && git -C /tmp/jg -c user.name=t -c user.email=t@t commit -qm x
.venv/bin/guardian scan /tmp/jg --out guardian-out/sample-java-gradle
```
