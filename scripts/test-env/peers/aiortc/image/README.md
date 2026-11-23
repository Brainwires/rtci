`sdp.py` is aiortc's `src/aiortc/sdp.py` from the fork https://github.com/Brainwires/aiortc,
branch `fix/extmap-extension-attributes-1.16.0`, commit 4982300 (aiortc 1.16.0 plus the fix for
https://github.com/aiortc/aiortc/issues/1492), unmodified; BSD-3-Clause, `LICENSE.aiortc`.
Test-image content only (the Dockerfile overlays it on the 1.16.0 wheel): it is part of no
crate, and the `rtc` package excludes `scripts/test-env/peers/`. To be dropped when upstream
releases the fix.
