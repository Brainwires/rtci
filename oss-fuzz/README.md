# OSS-Fuzz build files

This project is not enrolled in [OSS-Fuzz](https://github.com/google/oss-fuzz): there is no
`projects/` entry for it there, so these files are not used by OSS-Fuzz today. They are kept
because they are the build an enrolment would use, and because `build.sh` lists every fuzz
crate (`FUZZ_CRATES`), which `scripts/check-fuzz-registry.py` checks against the fuzz
directories and `.github/workflows/fuzz.yml`.

- `Dockerfile`: the build image, on `gcr.io/oss-fuzz-base/base-builder-rust`.
- `build.sh`: builds every target of every fuzz crate into `$OUT`.

The project file OSS-Fuzz requires (`project.yaml`, with the project's homepage and a
security contact address) is written at enrolment. Security reports go through the
repository's private vulnerability reporting (`SECURITY.md`).
