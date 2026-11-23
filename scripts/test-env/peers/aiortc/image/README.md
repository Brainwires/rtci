`sdp.py` and `rtp.py` are aiortc's `src/aiortc/sdp.py` and `src/aiortc/rtp.py` from the fork
https://github.com/Brainwires/aiortc, branch `fix/extmap-extension-attributes-1.16.0`, commit
2245f90 (aiortc 1.16.0 plus two fixes: `a=extmap` extension attributes,
https://github.com/aiortc/aiortc/issues/1492, and RTCP SDES chunk alignment, RFC 3550 6.5),
unmodified; BSD-3-Clause, `LICENSE.aiortc`. Test-image content only (the Dockerfile overlays them
on the 1.16.0 wheel): they are part of no crate, and the `rtc` package excludes
`scripts/test-env/peers/`. To be dropped when upstream releases the fixes.
