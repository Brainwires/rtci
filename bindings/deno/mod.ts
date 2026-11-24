/**
 * A reference Deno binding of rtc-ffi's driven layer: the browser's WebRTC classes
 * (`RTCPeerConnection`, `RTCDataChannel`, `RTCRtpTransceiver` / `Sender` / `Receiver`,
 * `RTCSessionDescription`, `RTCIceCandidate`, events, `getStats`) over `Deno.dlopen`.
 *
 * Not a published package: the Denext project maintains its own binding; this one shows how
 * the C interface maps onto the browser API. Run with `--allow-ffi` (and `--allow-env` for
 * `RTC_FFI_LIB`).
 *
 * The engine captures and encodes nothing: a local track is a kind and ids, and the
 * application writes encoded frames (`RTCRtpSender.writeFrame`) or RTP packets
 * (`RTCRtpSender.writeRtp`), and receives RTP (`RTCRtpReceiver`'s `rtp` event).
 *
 * The library: `RTC_FFI_LIB` when set, else `librtc_ffi.{so,dylib}` / `rtc_ffi.dll` beside
 * this module. Nothing is downloaded.
 *
 * @module
 */

const RTC_OK = 0;
const RTC_EMPTY = 1;
const RTC_ERR_BUFFER_TOO_SMALL = -2;
const RTC_ERR_CLOSED = -8;
/** The C interface version this binding was written for (`rtc_abi_version`). */
export const ABI_VERSION = 1;

function libraryFileName(): string {
  switch (Deno.build.os) {
    case "darwin":
      return "librtc_ffi.dylib";
    case "windows":
      return "rtc_ffi.dll";
    default:
      return "librtc_ffi.so";
  }
}

/** Where the library is loaded from: `RTC_FFI_LIB`, else beside this module. */
export function libraryPath(): string {
  let fromEnv: string | undefined;
  try {
    fromEnv = Deno.env.get("RTC_FFI_LIB");
  } catch {
    // No --allow-env: the path beside the module.
  }
  if (fromEnv) return fromEnv;
  const url = new URL(`./${libraryFileName()}`, import.meta.url);
  if (url.protocol !== "file:") {
    throw new Error(
      `rtc-ffi: ${url} is not a local file; set RTC_FFI_LIB to the library's path`,
    );
  }
  const path = decodeURIComponent(url.pathname);
  return Deno.build.os === "windows" ? path.replace(/^\/([A-Za-z]:)/, "$1") : path;
}

const symbols = {
  rtc_abi_version: { parameters: [], result: "u32" },
  rtc_last_error: { parameters: ["buffer", "usize"], result: "usize" },
  rtc_string_free: { parameters: ["pointer"], result: "void" },
  rtc_mux_new: { parameters: ["buffer", "buffer"], result: "i32" },
  rtc_mux_addresses: { parameters: ["pointer", "buffer"], result: "i32" },
  rtc_mux_free: { parameters: ["pointer"], result: "void" },
  rtc_driven_new: {
    parameters: ["buffer", "buffer", "buffer", "pointer", "buffer"],
    result: "i32",
  },
  rtc_driven_call: {
    parameters: ["pointer", "buffer", "buffer", "buffer", "usize", "buffer"],
    result: "i32",
  },
  rtc_driven_wait: { parameters: ["pointer", "u32"], result: "i32", nonblocking: true },
  rtc_driven_next: {
    parameters: ["pointer", "buffer", "usize", "buffer", "buffer"],
    result: "i32",
  },
  rtc_driven_close: { parameters: ["pointer"], result: "i32", nonblocking: true },
  rtc_driven_free: { parameters: ["pointer"], result: "void" },
} as const;

type Library = Deno.DynamicLibrary<typeof symbols>;
let library: Library | undefined;

function lib(): Library["symbols"] {
  if (!library) {
    library = Deno.dlopen(libraryPath(), symbols);
    const abi = library.symbols.rtc_abi_version();
    if (abi !== ABI_VERSION) {
      library.close();
      library = undefined;
      throw new Error(`rtc-ffi: the library has ABI ${abi}, this binding ${ABI_VERSION}`);
    }
  }
  return library.symbols;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function cstr(s: string | null | undefined): Uint8Array<ArrayBuffer> | null {
  if (s === null || s === undefined) return null;
  const bytes = encoder.encode(s);
  const out = new Uint8Array(bytes.length + 1);
  out.set(bytes);
  return out;
}

function lastError(): string {
  const buf = new Uint8Array(4096);
  const n = Number(lib().rtc_last_error(buf, BigInt(buf.length)));
  return decoder.decode(buf.subarray(0, Math.min(n, buf.length - 1)));
}

/** An error of the library: its status code and message. */
export class RtcError extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
    this.name = code === -3 ? "OperationError" : "RtcError";
  }
}

function check(code: number, what: string): void {
  if (code < 0) throw new RtcError(code, `${what}: ${lastError()}`);
}

function takeString(out: BigUint64Array<ArrayBuffer>): string {
  const ptr = Deno.UnsafePointer.create(out[0]);
  if (!ptr) return "null";
  const s = new Deno.UnsafePointerView(ptr).getCString();
  lib().rtc_string_free(ptr);
  return s;
}

/** The non-standard options of a server: the second argument of `RTCPeerConnection`. */
export interface RTCServerOptions {
  /** Only these local addresses get candidates (default: every interface address). */
  bindAddresses?: string[];
  /** Loopback addresses too. */
  includeLoopback?: boolean;
  /** IPv6 link-local addresses too. */
  includeLinkLocal?: boolean;
  /** UDP sockets and ICE-TCP listeners take ports of this range. */
  portRange?: { min: number; max: number };
  /** The engine's own TCP (ICE-TCP, TURN over TCP / TLS); on by default. */
  tcp?: boolean;
  /** 1:1 NAT: this host's public addresses. */
  natIps?: string[];
  /** `"host"` (default) or `"srflx"`. */
  natCandidateType?: "host" | "srflx";
  /** ICE-lite. */
  iceLite?: boolean;
  /** A UDP (and TCP) port shared with other peer connections. */
  sharedPort?: RTCSharedPort;
  /** Engine settings (rtc-ffi's settings JSON: `answeringDtlsRole`, `iceTimeouts`, ...). */
  settings?: Record<string, unknown>;
}

/** One UDP port, and optionally one ICE-TCP port, shared by many peer connections. */
export class RTCSharedPort {
  #handle: Deno.PointerValue;
  readonly udp: string;
  readonly tcp: string | null;

  constructor(options: { udp: string; tcp?: string }) {
    const out = new BigUint64Array(1);
    check(lib().rtc_mux_new(cstr(JSON.stringify(options)), out), "RTCSharedPort");
    this.#handle = Deno.UnsafePointer.create(out[0]);
    const addresses = new BigUint64Array(1);
    check(lib().rtc_mux_addresses(this.#handle, addresses), "RTCSharedPort");
    const parsed = JSON.parse(takeString(addresses));
    this.udp = parsed.udp;
    this.tcp = parsed.tcp;
  }

  /** @internal */
  get handle(): Deno.PointerValue {
    return this.#handle;
  }

  /** Closes the port; close its peer connections first. */
  close(): void {
    if (this.#handle) lib().rtc_mux_free(this.#handle);
    this.#handle = null;
  }
}

export type RTCSdpType = "offer" | "answer" | "pranswer" | "rollback";

export interface RTCSessionDescriptionInit {
  type: RTCSdpType;
  sdp?: string;
}

export class RTCSessionDescription {
  readonly type: RTCSdpType;
  readonly sdp: string;
  constructor(init: RTCSessionDescriptionInit) {
    this.type = init.type;
    this.sdp = init.sdp ?? "";
  }
  toJSON(): RTCSessionDescriptionInit {
    return { type: this.type, sdp: this.sdp };
  }
}

export interface RTCIceCandidateInit {
  candidate?: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
  usernameFragment?: string | null;
}

export class RTCIceCandidate {
  readonly candidate: string;
  readonly sdpMid: string | null;
  readonly sdpMLineIndex: number | null;
  readonly usernameFragment: string | null;
  constructor(init: RTCIceCandidateInit = {}) {
    this.candidate = init.candidate ?? "";
    this.sdpMid = init.sdpMid ?? null;
    this.sdpMLineIndex = init.sdpMLineIndex ?? null;
    this.usernameFragment = init.usernameFragment ?? null;
  }
  toJSON(): RTCIceCandidateInit {
    return {
      candidate: this.candidate,
      sdpMid: this.sdpMid,
      sdpMLineIndex: this.sdpMLineIndex,
      usernameFragment: this.usernameFragment,
    };
  }
}

export class RTCPeerConnectionIceEvent extends Event {
  readonly candidate: RTCIceCandidate | null;
  readonly url: string | null;
  constructor(candidate: RTCIceCandidate | null, url: string | null) {
    super("icecandidate");
    this.candidate = candidate;
    this.url = url;
  }
}

export class RTCDataChannelEvent extends Event {
  constructor(readonly channel: RTCDataChannel) {
    super("datachannel");
  }
}

/** The remote track of a receiver: an id and a kind (the engine decodes nothing). */
export class RTCRemoteTrack {
  constructor(readonly id: string, readonly kind: string) {}
}

export class RTCTrackEvent extends Event {
  constructor(
    readonly receiver: RTCRtpReceiver,
    readonly transceiver: RTCRtpTransceiver,
    readonly track: RTCRemoteTrack,
    readonly streams: string[],
  ) {
    super("track");
  }
}

/** An RTP (or RTCP) packet received, in its wire form (decrypted). */
export class RTCRtpPacketEvent extends Event {
  constructor(type: "rtp" | "rtcp", readonly data: Uint8Array, readonly arrivalNs: number) {
    super(type);
  }
}

/** A local track to send: the application encodes; the engine packetizes or forwards. */
export interface RTCLocalTrack {
  kind: "audio" | "video";
  id?: string;
  label?: string;
  /** The SSRC to send with (generated when absent). */
  ssrc?: number;
  /** The codec to send (`{mimeType, clockRate, channels, sdpFmtpLine}`); Opus or VP8 when absent. */
  codec?: { mimeType: string; clockRate: number; channels?: number; sdpFmtpLine?: string };
}

export class RTCRtpSender {
  constructor(
    readonly pc: RTCPeerConnection,
    readonly id: number,
    readonly track: RTCLocalTrack | null,
  ) {}

  /** The negotiated codecs and the SSRCs (rtc-ffi's `senderInfo`). */
  getParameters(): {
    ssrcs: number[];
    codecs: { payloadType: number; mimeType: string; clockRate: number }[];
  } {
    return this.pc._call("senderInfo", { sender: this.id });
  }

  /** Sends one encoded frame; the RTP timestamp advances by `samples` after it. */
  writeFrame(frame: Uint8Array, samples: number): void {
    this.pc._call("writeFrame", { sender: this.id, samples }, frame);
  }

  /** Sends one RTP packet (its wire form). */
  writeRtp(packet: Uint8Array): void {
    this.pc._call("writeRtp", { sender: this.id }, packet);
  }
}

export class RTCRtpReceiver extends EventTarget {
  onrtp: ((event: RTCRtpPacketEvent) => void) | null = null;
  onrtcp: ((event: RTCRtpPacketEvent) => void) | null = null;
  constructor(readonly pc: RTCPeerConnection, readonly id: number, readonly track: RTCRemoteTrack) {
    super();
  }

  getParameters(): { codecs: { payloadType: number; mimeType: string; clockRate: number }[] } {
    return this.pc._call("receiverInfo", { receiver: this.id });
  }

  getStats(): Promise<Map<string, Record<string, unknown>>> {
    return Promise.resolve(statsMap(this.pc._call("getStats", { selector: "receiver", id: this.id })));
  }

  /** @internal */
  _deliver(event: RTCRtpPacketEvent): void {
    (event.type === "rtp" ? this.onrtp : this.onrtcp)?.call(this, event);
    this.dispatchEvent(event);
  }
}

export type RTCRtpTransceiverDirection =
  | "sendrecv"
  | "sendonly"
  | "recvonly"
  | "inactive"
  | "stopped";

export class RTCRtpTransceiver {
  constructor(
    readonly pc: RTCPeerConnection,
    readonly id: number,
    readonly sender: RTCRtpSender,
    readonly receiver: RTCRtpReceiver,
  ) {}

  #info(): Record<string, unknown> | undefined {
    const list = this.pc._call("transceivers", null) as Record<string, unknown>[];
    return list.find((t) => t.id === this.id);
  }

  get mid(): string | null {
    return (this.#info()?.mid as string | null) ?? null;
  }

  get direction(): RTCRtpTransceiverDirection {
    return (this.#info()?.direction as RTCRtpTransceiverDirection) ?? "stopped";
  }

  set direction(direction: RTCRtpTransceiverDirection) {
    this.pc._call("setDirection", { transceiver: this.id, direction });
  }

  get currentDirection(): RTCRtpTransceiverDirection | null {
    return (this.#info()?.currentDirection as RTCRtpTransceiverDirection | null) ?? null;
  }

  stop(): void {
    this.pc._call("stopTransceiver", { transceiver: this.id });
  }
}

export type RTCDataChannelState = "connecting" | "open" | "closing" | "closed";

export interface RTCDataChannelInit {
  ordered?: boolean;
  maxPacketLifeTime?: number;
  maxRetransmits?: number;
  protocol?: string;
  negotiated?: boolean;
  id?: number;
  priority?: "very-low" | "low" | "medium" | "high";
}

export class RTCDataChannel extends EventTarget {
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclosing: ((event: Event) => void) | null = null;
  onclose: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onbufferedamountlow: ((event: Event) => void) | null = null;
  binaryType: "arraybuffer" = "arraybuffer";
  #state: RTCDataChannelState = "connecting";
  #info: Record<string, unknown>;

  constructor(readonly pc: RTCPeerConnection, readonly channel: number) {
    super();
    this.#info = pc._call("dataChannelInfo", { channel });
    if (this.#info.readyState) this.#state = this.#info.readyState as RTCDataChannelState;
  }

  get label(): string {
    return this.#info.label as string;
  }
  get protocol(): string {
    return (this.#info.protocol as string) ?? "";
  }
  get ordered(): boolean {
    return (this.#info.ordered as boolean) ?? true;
  }
  get negotiated(): boolean {
    return (this.#info.negotiated as boolean) ?? false;
  }
  /** The SCTP stream id (null until the DTLS role is known). */
  get id(): number | null {
    return this.pc._call("dataChannelInfo", { channel: this.channel }).id ?? null;
  }
  get readyState(): RTCDataChannelState {
    return this.#state;
  }
  get bufferedAmount(): number {
    return this.pc._call("dataChannelInfo", { channel: this.channel }).bufferedAmount ?? 0;
  }
  set bufferedAmountLowThreshold(threshold: number) {
    this.pc._call("setBufferedAmountLowThreshold", { channel: this.channel, threshold });
  }

  send(data: string | ArrayBuffer | ArrayBufferView): void {
    if (typeof data === "string") {
      this.pc._call("dataChannelSend", { channel: this.channel, isString: true }, encoder.encode(data));
    } else {
      const bytes = data instanceof ArrayBuffer
        ? new Uint8Array(data)
        : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      this.pc._call("dataChannelSend", { channel: this.channel, isString: false }, bytes);
    }
  }

  close(): void {
    this.pc._call("dataChannelClose", { channel: this.channel });
  }

  /** @internal */
  _event(type: string): void {
    if (type === "open" || type === "closing" || type === "close") {
      this.#state = type === "close" ? "closed" : type === "open" ? "open" : "closing";
    }
    const event = new Event(type);
    const handler = {
      open: this.onopen,
      closing: this.onclosing,
      close: this.onclose,
      error: this.onerror,
      bufferedamountlow: this.onbufferedamountlow,
    }[type];
    handler?.call(this, event);
    this.dispatchEvent(event);
  }

  /** @internal */
  _message(isString: boolean, data: Uint8Array): void {
    const event = new MessageEvent("message", {
      data: isString ? decoder.decode(data) : data.slice().buffer,
    });
    this.onmessage?.call(this, event);
    this.dispatchEvent(event);
  }
}

export interface RTCIceServer {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface RTCConfiguration {
  iceServers?: RTCIceServer[];
  iceTransportPolicy?: "all" | "relay";
  bundlePolicy?: "balanced" | "max-compat" | "max-bundle";
  rtcpMuxPolicy?: "require";
  iceCandidatePoolSize?: number;
}

function statsMap(report: Record<string, Record<string, unknown>>): Map<string, Record<string, unknown>> {
  return new Map(Object.entries(report ?? {}));
}

type Handler<E extends Event = Event> = ((event: E) => void) | null;

export class RTCPeerConnection extends EventTarget {
  onicecandidate: Handler<RTCPeerConnectionIceEvent> = null;
  ontrack: Handler<RTCTrackEvent> = null;
  ondatachannel: Handler<RTCDataChannelEvent> = null;
  onnegotiationneeded: Handler = null;
  onsignalingstatechange: Handler = null;
  oniceconnectionstatechange: Handler = null;
  onicegatheringstatechange: Handler = null;
  onconnectionstatechange: Handler = null;
  onicecandidateerror: Handler = null;

  #handle: Deno.PointerValue;
  #closing = false;
  #pump: Promise<void>;
  #buffer = new Uint8Array(1 << 18);
  #channels = new Map<number, RTCDataChannel>();
  #transceivers = new Map<number, RTCRtpTransceiver>();
  #localTracks = new Map<number, RTCLocalTrack>();
  #states = {
    signalingState: "stable",
    iceConnectionState: "new",
    iceGatheringState: "new",
    connectionState: "new",
  };

  constructor(configuration: RTCConfiguration = {}, options: RTCServerOptions = {}) {
    super();
    const { settings, sharedPort, ...driver } = options;
    const out = new BigUint64Array(1);
    check(
      lib().rtc_driven_new(
        cstr(JSON.stringify(configuration)),
        cstr(settings ? JSON.stringify(settings) : null),
        cstr(JSON.stringify(driver)),
        sharedPort?.handle ?? null,
        out,
      ),
      "RTCPeerConnection",
    );
    this.#handle = Deno.UnsafePointer.create(out[0]);
    this.#pump = this.#run();
  }

  /** @internal Calls a method of the driven layer; the result's JSON parsed. */
  // deno-lint-ignore no-explicit-any
  _call(method: string, params: unknown, data?: Uint8Array): any {
    if (!this.#handle) throw new RtcError(RTC_ERR_CLOSED, "InvalidStateError: closed");
    const out = new BigUint64Array(1);
    const bytes = data ?? new Uint8Array(0);
    check(
      lib().rtc_driven_call(
        this.#handle,
        cstr(method),
        cstr(params === null || params === undefined ? null : JSON.stringify(params)),
        bytes as Uint8Array<ArrayBuffer>,
        BigInt(bytes.length),
        out,
      ),
      method,
    );
    return JSON.parse(takeString(out));
  }

  async #run(): Promise<void> {
    while (!this.#closing) {
      const code = await lib().rtc_driven_wait(this.#handle, 100);
      if (code === RTC_OK) this.#drain();
      else if (code !== RTC_EMPTY) break;
    }
    this.#drain();
  }

  #drain(): void {
    if (!this.#handle) return;
    const jsonLen = new BigUint64Array(1);
    const dataLen = new BigUint64Array(1);
    for (;;) {
      const code = lib().rtc_driven_next(
        this.#handle,
        this.#buffer,
        BigInt(this.#buffer.length),
        jsonLen,
        dataLen,
      );
      if (code === RTC_EMPTY) return;
      if (code === RTC_ERR_BUFFER_TOO_SMALL) {
        this.#buffer = new Uint8Array(Number(jsonLen[0] + dataLen[0]) * 2);
        continue;
      }
      check(code, "rtc_driven_next");
      const j = Number(jsonLen[0]);
      const item = JSON.parse(decoder.decode(this.#buffer.subarray(0, j)));
      const data = this.#buffer.slice(j, j + Number(dataLen[0]));
      try {
        this.#dispatch(item, data);
      } catch (e) {
        // An exception in a handler does not stop the pump, as in a browser.
        queueMicrotask(() => {
          throw e;
        });
      }
    }
  }

  #fire<E extends Event>(event: E, handler: Handler<E>): void {
    handler?.call(this, event);
    this.dispatchEvent(event);
  }

  #transceiver(id: number): RTCRtpTransceiver {
    let t = this.#transceivers.get(id);
    if (!t) {
      let track = new RTCRemoteTrack("", "");
      try {
        const info = this._call("receiverInfo", { receiver: id });
        track = new RTCRemoteTrack(info.track, info.kind);
      } catch {
        // A transceiver without a receiver yet.
      }
      t = new RTCRtpTransceiver(
        this,
        id,
        new RTCRtpSender(this, id, this.#localTracks.get(id) ?? null),
        new RTCRtpReceiver(this, id, track),
      );
      this.#transceivers.set(id, t);
    }
    return t;
  }

  #channel(id: number): RTCDataChannel {
    let c = this.#channels.get(id);
    if (!c) {
      c = new RTCDataChannel(this, id);
      this.#channels.set(id, c);
    }
    return c;
  }

  // deno-lint-ignore no-explicit-any
  #dispatch(item: any, data: Uint8Array): void {
    switch (item.type) {
      case "icecandidate":
        this.#fire(
          new RTCPeerConnectionIceEvent(
            item.candidate ? new RTCIceCandidate(item.candidate) : null,
            item.url ?? null,
          ),
          this.onicecandidate,
        );
        break;
      case "icecandidateerror":
        this.#fire(new Event("icecandidateerror"), this.onicecandidateerror);
        break;
      case "negotiationneeded":
        this.#fire(new Event("negotiationneeded"), this.onnegotiationneeded);
        break;
      case "signalingstatechange":
        this.#states.signalingState = item.state;
        this.#fire(new Event(item.type), this.onsignalingstatechange);
        break;
      case "iceconnectionstatechange":
        this.#states.iceConnectionState = item.state;
        this.#fire(new Event(item.type), this.oniceconnectionstatechange);
        break;
      case "icegatheringstatechange":
        this.#states.iceGatheringState = item.state;
        this.#fire(new Event(item.type), this.onicegatheringstatechange);
        break;
      case "connectionstatechange":
        this.#states.connectionState = item.state;
        this.#fire(new Event(item.type), this.onconnectionstatechange);
        break;
      case "datachannel":
        this.#fire(new RTCDataChannelEvent(this.#channel(item.channel)), this.ondatachannel);
        break;
      case "track": {
        const t = this.#transceiver(item.transceiver);
        this.#fire(new RTCTrackEvent(t.receiver, t, t.receiver.track, item.streams ?? []), this.ontrack);
        break;
      }
      case "message":
        this.#channel(item.channel)._message(item.isString, data);
        break;
      case "rtp":
      case "rtcp":
        this.#transceivers.get(item.receiver)?.receiver._deliver(
          new RTCRtpPacketEvent(item.type, data, item.nowNs),
        );
        break;
      default:
        if (item.target === "datachannel" && typeof item.channel === "number") {
          this.#channel(item.channel)._event(item.type);
        }
    }
  }

  #live(name: keyof RTCPeerConnection["_states"]): string {
    if (!this.#handle || this.#closing) return this.#states[name];
    return this._call("states", null)[name];
  }
  /** @internal The states as the events last reported them. */
  get _states(): {
    signalingState: string;
    iceConnectionState: string;
    iceGatheringState: string;
    connectionState: string;
  } {
    return this.#states;
  }
  get signalingState(): string {
    return this.#live("signalingState");
  }
  get iceConnectionState(): string {
    return this.#live("iceConnectionState");
  }
  get iceGatheringState(): string {
    return this.#live("iceGatheringState");
  }
  get connectionState(): string {
    return this.#live("connectionState");
  }

  #description(which: number): RTCSessionDescription | null {
    const d = this._call("description", { which });
    return d ? new RTCSessionDescription(d) : null;
  }
  get localDescription(): RTCSessionDescription | null {
    return this.#description(0);
  }
  get currentLocalDescription(): RTCSessionDescription | null {
    return this.#description(1);
  }
  get pendingLocalDescription(): RTCSessionDescription | null {
    return this.#description(2);
  }
  get remoteDescription(): RTCSessionDescription | null {
    return this.#description(3);
  }
  get currentRemoteDescription(): RTCSessionDescription | null {
    return this.#description(4);
  }
  get pendingRemoteDescription(): RTCSessionDescription | null {
    return this.#description(5);
  }

  createOffer(options?: { iceRestart?: boolean }): Promise<RTCSessionDescriptionInit> {
    return Promise.resolve().then(() => this._call("createOffer", options ?? null));
  }

  createAnswer(): Promise<RTCSessionDescriptionInit> {
    return Promise.resolve().then(() => this._call("createAnswer", null));
  }

  /** With no argument, makes the offer or answer the signaling state calls for. */
  async setLocalDescription(description?: RTCSessionDescriptionInit): Promise<void> {
    if (!description || !description.sdp) {
      const type = description?.type ??
        (this.signalingState === "have-remote-offer" ? "answer" : "offer");
      description = type === "answer" ? await this.createAnswer() : await this.createOffer();
    }
    this._call("setLocalDescription", { type: description.type, sdp: description.sdp ?? "" });
  }

  setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
    return Promise.resolve().then(() =>
      this._call("setRemoteDescription", { type: description.type, sdp: description.sdp ?? "" })
    );
  }

  addIceCandidate(candidate?: RTCIceCandidateInit | null): Promise<void> {
    return Promise.resolve().then(() => this._call("addIceCandidate", candidate ?? null));
  }

  restartIce(): void {
    this._call("restartIce", null);
  }

  setConfiguration(configuration: RTCConfiguration): void {
    this._call("setConfiguration", configuration);
  }

  createDataChannel(label: string, init: RTCDataChannelInit = {}): RTCDataChannel {
    const { channel } = this._call("createDataChannel", { label, init });
    return this.#channel(channel);
  }

  /** Adds a local track; `streams` are stream ids. */
  addTrack(track: RTCLocalTrack, ...streams: string[]): RTCRtpSender {
    const id = track.id ?? crypto.randomUUID();
    const { sender } = this._call("addTrack", {
      kind: track.kind,
      id,
      label: track.label ?? id,
      streamIds: streams,
      ssrc: track.ssrc,
      codec: track.codec,
    });
    this.#localTracks.set(sender, { ...track, id });
    this.#transceivers.delete(sender);
    return this.#transceiver(sender).sender;
  }

  removeTrack(sender: RTCRtpSender): void {
    this._call("removeTrack", { sender: sender.id });
  }

  addTransceiver(
    kind: "audio" | "video",
    init: { direction?: RTCRtpTransceiverDirection; streams?: string[] } = {},
  ): RTCRtpTransceiver {
    const { transceiver } = this._call("addTransceiver", { kind, init });
    return this.#transceiver(transceiver);
  }

  getTransceivers(): RTCRtpTransceiver[] {
    const list = this._call("transceivers", null) as { id: number }[];
    return list.map((t) => this.#transceiver(t.id));
  }

  getSenders(): RTCRtpSender[] {
    return this.getTransceivers().map((t) => t.sender);
  }

  getReceivers(): RTCRtpReceiver[] {
    return this.getTransceivers().map((t) => t.receiver);
  }

  getStats(): Promise<Map<string, Record<string, unknown>>> {
    return Promise.resolve().then(() => statsMap(this._call("getStats", null)));
  }

  /** The bound sockets (non-standard): `{udp: [...], mux, muxTcp}`. */
  localAddresses(): { udp: string[]; mux: string | null; muxTcp: string | null } {
    return this._call("localAddresses", null);
  }

  /** Closes the connection (the remote is told), stops the thread and frees the handle. */
  async close(): Promise<void> {
    if (!this.#handle || this.#closing) return;
    this.#closing = true;
    this.#states.signalingState = "closed";
    this.#states.connectionState = "closed";
    await lib().rtc_driven_close(this.#handle);
    await this.#pump;
    for (const c of this.#channels.values()) {
      if (c.readyState !== "closed") c._event("close");
    }
    lib().rtc_driven_free(this.#handle);
    this.#handle = null;
  }
}
