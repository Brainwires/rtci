/**
 * Two peer connections in one process, over loopback: a data channel echo and Opus frames,
 * the second peer on a shared port. Run from the repository root after building the library:
 *
 *     cargo build -p rtci-ffi --release
 *     RTCI_FFI_LIB=target/release/librtci_ffi.so deno run --allow-ffi --allow-env bindings/deno/example.ts
 *
 * (`librtci_ffi.dylib` on macOS, `rtci_ffi.dll` on Windows.) Exits 0 once the echo and an RTP
 * packet have arrived.
 */
import { RTCPeerConnection, RTCSharedPort } from "./mod.ts";

const local = { bindAddresses: ["127.0.0.1"], includeLoopback: true, tcp: false };
const port = new RTCSharedPort({ udp: "127.0.0.1:0" });
const a = new RTCPeerConnection({}, local);
const b = new RTCPeerConnection({}, { sharedPort: port, tcp: false });

a.onicecandidate = (e) => e.candidate && b.addIceCandidate(e.candidate).catch(() => {});
b.onicecandidate = (e) => e.candidate && a.addIceCandidate(e.candidate).catch(() => {});

const gotEcho = Promise.withResolvers<string>();
const gotRtp = Promise.withResolvers<Uint8Array>();

b.ondatachannel = ({ channel }) => {
  channel.onmessage = (e) => channel.send(`echo: ${e.data}`);
};
b.ontrack = ({ receiver }) => {
  receiver.onrtp = (e) => gotRtp.resolve(e.data);
};

const channel = a.createDataChannel("example");
channel.onopen = () => channel.send("hello from Deno");
channel.onmessage = (e) => gotEcho.resolve(e.data as string);
const sender = a.addTrack({ kind: "audio", id: "mic" }, "stream");

await a.setLocalDescription();
await b.setRemoteDescription(a.localDescription!);
await b.setLocalDescription();
await a.setRemoteDescription(b.localDescription!);

const ticker = setInterval(() => {
  if (a.connectionState === "connected") sender.writeFrame(new Uint8Array([0xfc, 1, 2, 3]), 960);
}, 20);
const timeout = setTimeout(() => {
  console.error("timed out", a.connectionState, b.connectionState);
  Deno.exit(1);
}, 20_000);

console.log(await gotEcho.promise);
console.log("rtp", (await gotRtp.promise).length, "bytes");
const stats = await b.getStats();
console.log("stats:", [...stats.values()].map((s) => s.type).join(", "));
clearInterval(ticker);
clearTimeout(timeout);
await a.close();
await b.close();
port.close();
