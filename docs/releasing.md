# Releasing

How a release of the workspace is published to crates.io and tagged. It is done by hand, by
someone who owns the crates on crates.io; `.github/workflows/release.yml` makes the GitHub
release from the tag and has the same publication list, commented out.

crates.io versions are permanent: a version that has been published can never be published
again or deleted. Yanking (`cargo yank`) is the only undo, and it only stops new lock files from
choosing the version. Read the whole procedure before starting.

## What is published

Nineteen crates, all at the workspace version. Dependencies come first: normal and build
dependencies, and dev-dependencies that carry a version (cargo keeps those in the published
manifest, so they must resolve on crates.io too).

1. `rtc-crypto`
2. `rtc-interceptor-derive`
3. `rtc-sframe`
4. `rtc-shared`
5. `rtc-dtls`
6. `rtc-mdns`
7. `rtc-rtcp`
8. `rtc-rtp`
9. `rtc-interceptor`
10. `rtc-media`
11. `rtc-sctp`
12. `rtc-datachannel`
13. `rtc-sdp`
14. `rtc-srtp`
15. `rtc-stun`
16. `rtc-ice`
17. `rtc-turn`
18. `rtc`
19. `rtc-stream-driver` (its default feature `peer` depends on `rtc`; the root crate's
    dev-dependency on it has no version, so `cargo publish` drops it)

Not published (`publish = false`): `rtc-signal` (the examples' signalling helper; the root
crate's dev-dependency on it has no version, so `cargo publish` drops it), the fuzz crates
(`fuzz/`, `rtc-*/fuzz/`), the benchmark (`benchmarks/aead-gcm`) and the test environment's
peers (`scripts/test-env/peers/`). The root crate's package holds the library sources, the README
and the licence texts only (`include` in `Cargo.toml`): the examples, integration tests,
fixtures and documentation stay in the repository.

The order is what `cargo metadata` gives (`python3 scripts/rename-to-rtci.py --dry-run`
prints it). When a crate gains or loses a dependency on another crate of the workspace,
regenerate the list and update this file and release.yml.

## Before

1. The release commit is on `master` and its CI is green (cargo, fuzz, test environment).
2. `CHANGELOG.md`: the `## [Unreleased]` section becomes `## [X.Y.Z] - YYYY-MM-DD`, with a new
   empty `## [Unreleased]` above it. The version in `[workspace.package]` and in every
   `[workspace.dependencies]` requirement on a workspace crate is `X.Y.Z`.
3. `SECURITY.md`'s supported-versions table names the new line if it is a new minor version.
4. A crates.io API token with the `publish-new` and `publish-update` scopes, given to cargo
   with `cargo login` (it stays in `~/.cargo/credentials.toml`; never commit it or put it in
   the repository's secrets until publishing moves to CI).

## Dry runs

From a clean checkout of the release commit:

```sh
# What goes into each package, and nothing large or unintended
for p in rtc-crypto rtc-interceptor-derive rtc-sframe rtc-shared rtc-dtls rtc-mdns rtc-rtcp \
         rtc-rtp rtc-interceptor rtc-media rtc-sctp rtc-datachannel rtc-sdp rtc-srtp \
         rtc-stun rtc-ice rtc-turn rtc rtc-stream-driver; do
  cargo package --list -p "$p" > "/tmp/$p.files"
done

# Package and build every publishable crate. With several packages, cargo resolves the
# workspace's own not-yet-published crates from the packages it has just made, so this
# works before anything is on crates.io.
cargo publish --workspace --dry-run

# A crate whose workspace dependencies are already on crates.io (or that has none) can be
# checked on its own as well:
cargo publish --dry-run -p rtc-crypto
```

`cargo publish -p <crate> --dry-run` on a crate whose workspace dependencies are not yet on
crates.io fails with "no matching package named ..." (or "failed to select a version"): that is
expected before the first publish and says nothing about the crate. The dry runs must otherwise
finish without errors; warnings about example and test targets "not included in the published
package" are the root crate's `include` at work.

## Publish

Either the whole workspace in one command, in dependency order, stopping at the first failure:

```sh
cargo publish --workspace
```

or one crate at a time, in the order above:

```sh
cargo publish -p rtc-crypto
cargo publish -p rtc-interceptor-derive
# ... every crate of the list, in order ...
cargo publish -p rtc
```

`cargo publish` returns only once the crate is in the crates.io index (it waits up to
`publish.timeout`, 60 seconds by default), so the next crate resolves it. If it reports a
timeout while waiting, the crate is published: wait a minute and go on with the next one.
crates.io limits how fast new crate names can be published; a `429 Too Many Requests` answer
names when to retry. Wait that long and publish the same crate again (nothing was published).

## When a publish fails midway

Nothing is rolled back: the crates already published stay published.

- **The failing crate was not uploaded** (verification failed, a network error, a rate limit):
  fix the cause if there is one, commit it, and continue the list from that crate. The crates
  published before were packaged from the earlier commit; that is fine as long as the fix does
  not change them. If it does change one of them, that crate needs a new patch version
  (`X.Y.Z+1`) published after the fix.
- **A crate was published broken** (wrong contents, a missing feature, a bad dependency
  requirement): it cannot be replaced. Yank it (`cargo yank --version X.Y.Z -p <crate>`), fix
  the cause, raise that crate's version to the next patch, publish it, and carry on. Dependents
  with the requirement `X.Y` accept the patch release without a change. Note the yank in
  `CHANGELOG.md`.
- Never re-tag or move a tag to describe a different commit.

## Tag and release notes

Once every crate is published:

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"      # on the commit the crates were published from
git push origin vX.Y.Z
```

The tag starts `.github/workflows/release.yml`: git-cliff (`cliff.toml`) writes the release
body from the conventional commits since the previous tag (breaking changes first, then one
section per kind, each capped with a link to `CHANGELOG.md`), and the GitHub release is
created. Read the generated release, and edit its text on GitHub where a summary of the
release's main changes at the top helps; `CHANGELOG.md` stays the full record.

After the tag:

- docs.rs builds each crate's documentation by itself, with the features its
  `[package.metadata.docs.rs]` names; check that every build passed.
- `semver.yml` compares later changes with this tag (`cargo semver-checks --baseline-rev`).
