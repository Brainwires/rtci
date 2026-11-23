// pion-peer: the Pion (github.com/pion/webrtc/v4) peer of the interop matrix. It runs one plan
// (scripts/test-env/peers/README.md) against examples/interop-peer over the browser page's
// WebSocket signalling and prints the result as the last line of stdout.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/interceptor"
	"github.com/pion/rtcp"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media"
	"github.com/pion/webrtc/v4/pkg/media/h264reader"
	"github.com/pion/webrtc/v4/pkg/media/ivfreader"
	"github.com/pion/webrtc/v4/pkg/media/oggreader"
	"golang.org/x/net/websocket"
)

// ---- the plan ----

type Step map[string]any

func (s Step) str(k string) string {
	v, _ := s[k].(string)
	return v
}

func (s Step) num(k string, def int) int {
	if v, ok := s[k].(float64); ok {
		return int(v)
	}
	return def
}

func (s Step) has(k string) bool {
	v, ok := s[k]
	return ok && v != nil
}

func (s Step) boolean(k string) bool {
	v, _ := s[k].(bool)
	return v
}

func (s Step) strs(k string) []string {
	arr, _ := s[k].([]any)
	out := []string{}
	for _, a := range arr {
		if v, ok := a.(string); ok {
			out = append(out, v)
		}
	}
	return out
}

type ICEServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type Plan struct {
	WS        string         `json:"ws"`
	Scenario  map[string]any `json:"scenario"`
	Media     string         `json:"media"`
	TimeoutMS int            `json:"timeout_ms"`
	Config    struct {
		ICEServers         []ICEServer `json:"iceServers"`
		ICETransportPolicy string      `json:"iceTransportPolicy"`
		Trickle            bool        `json:"trickle"`
		MDNS               bool        `json:"mdns"`
		TCP                bool        `json:"tcp"`
		BundlePolicy       string      `json:"bundlePolicy"`
		CAFile             string      `json:"caFile"`
	} `json:"config"`
	Steps []Step `json:"steps"`
}

// ---- the result ----

type Echo struct {
	Got   []any `json:"got"`
	Sizes []int `json:"sizes"`
}

type Count struct {
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
	Codec   string `json:"codec,omitempty"`
}

type StepResult struct {
	Op             string `json:"op"`
	OK             bool   `json:"ok"`
	MS             int64  `json:"ms"`
	Error          string `json:"error,omitempty"`
	SignalingState string `json:"signalingState,omitempty"`
}

type Result struct {
	OK              bool              `json:"ok"`
	Error           string            `json:"error"`
	NA              map[string]string `json:"na"`
	Version         string            `json:"version"`
	ConnectionState string            `json:"connectionState"`
	Steps           []StepResult      `json:"steps"`
	DataChannels    map[string]*Echo  `json:"datachannels"`
	RemoteChannels  map[string]string `json:"remoteChannels"`
	RTP             map[string]*Count `json:"rtp"`
	RTPSent         map[string]*Count `json:"rtpSent"`
	Coverage        []map[string]any  `json:"coverage"`
	RTCP            map[string]int    `json:"rtcp"`
	RTCPSent        map[string]int    `json:"rtcpSent"`
	TWCCSent        bool              `json:"twccSent"`
	SelectedPair    map[string]any    `json:"selectedPair"`
	DTLS            map[string]any    `json:"dtls"`
	SCTP            map[string]any    `json:"sctp"`
	LocalCandidates []string          `json:"localCandidates"`
	Trickled        int               `json:"trickled"`
	Descriptions    [][3]string       `json:"descriptions"`
	RemoteOffers    int               `json:"remoteOffers"`
	IgnoredOffers   int               `json:"ignoredOffers"`
	Rust            map[string]any    `json:"rust"`
	RustErrors      []string          `json:"rustErrors"`
}

// naError ends a run as not applicable: the stack cannot express the step.
type naError struct{ reason, cite string }

func (e naError) Error() string { return "na: " + e.reason }

// ---- sequence coverage of a received stream (RFC 3550 A.1 extended numbers) ----

type coverage struct {
	kind   string
	cycles uint64
	last   int
	seen   map[uint64]bool
	min    uint64
	max    uint64
}

func (c *coverage) add(seq uint16) {
	s := uint64(seq)
	var ext uint64
	if c.last < 0 {
		c.cycles = 1 << 16
		ext = c.cycles | s
	} else {
		diff := uint16(seq - uint16(c.last))
		switch {
		case diff < 0x8000:
			if seq < uint16(c.last) {
				c.cycles += 1 << 16
			}
			ext = c.cycles | s
		case seq > uint16(c.last):
			ext = (c.cycles - (1 << 16)) | s
		default:
			ext = c.cycles | s
		}
	}
	if c.last < 0 || uint16(seq-uint16(c.last)) < 0x8000 {
		c.last = int(seq)
	}
	if len(c.seen) == 0 {
		c.min, c.max = ext, ext
	}
	if ext < c.min {
		c.min = ext
	}
	if ext > c.max {
		c.max = ext
	}
	c.seen[ext] = true
}

// The span from the first to the last sequence number, leaving out the newest `tail`, and
// how many in it never arrived.
func (c *coverage) report(ssrc uint32, tail uint64) map[string]any {
	end := uint64(0)
	if c.max > tail {
		end = c.max - tail
	}
	span, missing := uint64(0), 0
	if len(c.seen) > 0 && end >= c.min {
		span = end - c.min + 1
		for s := c.min; s <= end; s++ {
			if !c.seen[s] {
				missing++
			}
		}
	}
	return map[string]any{"kind": c.kind, "ssrc": ssrc, "span": span, "missing": missing, "received": len(c.seen)}
}

// ---- the peer ----

type Peer struct {
	plan  Plan
	mu    sync.Mutex
	res   Result
	pc    *webrtc.PeerConnection
	ws    *websocket.Conn
	inbox chan map[string]any
	cands chan *webrtc.ICECandidate
	stdin *bufio.Reader

	sentScenario  bool
	lastSentSDP   string
	held          []webrtc.ICECandidateInit
	impolite      bool
	mungeRemote   string
	dcs           map[string]*webrtc.DataChannel
	senders       map[string]*webrtc.RTPSender
	stops         map[string]chan struct{}
	remoteVideo   []uint32
	cov           map[uint32]*coverage
	reports       int
	localSSRC     uint32
	answersSent   int
	answersGot    int
	deadline      time.Time
	gatherDone    bool
	gatheringWait bool
}

func main() {
	log.SetFlags(log.Lmicroseconds)
	log.SetOutput(os.Stderr)
	if len(os.Args) < 2 {
		log.Fatal("usage: pion-peer <plan.json>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	p := &Peer{
		inbox:   make(chan map[string]any, 256),
		cands:   make(chan *webrtc.ICECandidate, 256),
		stdin:   bufio.NewReader(os.Stdin),
		dcs:     map[string]*webrtc.DataChannel{},
		senders: map[string]*webrtc.RTPSender{},
		stops:   map[string]chan struct{}{},
		cov:     map[uint32]*coverage{},
	}
	if err := json.Unmarshal(raw, &p.plan); err != nil {
		log.Fatal(err)
	}
	p.res = Result{
		DataChannels: map[string]*Echo{}, RemoteChannels: map[string]string{},
		RTP: map[string]*Count{}, RTPSent: map[string]*Count{}, RTCP: map[string]int{}, RTCPSent: map[string]int{},
		LocalCandidates: []string{}, Descriptions: [][3]string{}, RustErrors: []string{}, Steps: []StepResult{},
		Coverage: []map[string]any{}, Version: pionVersion(),
	}
	if p.plan.TimeoutMS == 0 {
		p.plan.TimeoutMS = 60000
	}
	p.deadline = time.Now().Add(time.Duration(p.plan.TimeoutMS) * time.Millisecond)
	err = p.run()
	p.finish(err)
}

func pionVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/pion/webrtc/v4" {
				return d.Version
			}
		}
	}
	return ""
}

func (p *Peer) finish(err error) {
	if p.pc != nil {
		p.collect()
	}
	p.mu.Lock()
	var na naError
	switch {
	case errors.As(err, &na):
		p.res.NA = map[string]string{"reason": na.reason, "cite": na.cite}
		p.res.OK = false
	case err != nil:
		p.res.OK = false
		p.res.Error = err.Error()
	default:
		p.res.OK = true
	}
	if p.pc != nil {
		p.res.ConnectionState = p.pc.ConnectionState().String()
	}
	keys := make([]uint32, 0, len(p.cov))
	for k := range p.cov {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	p.res.Coverage = []map[string]any{}
	for _, k := range keys {
		p.res.Coverage = append(p.res.Coverage, p.cov[k].report(k, 50))
	}
	out, _ := json.Marshal(map[string]any{"result": p.res})
	p.mu.Unlock()
	fmt.Println(string(out))
	if p.pc != nil {
		_ = p.pc.Close()
	}
	if p.ws != nil {
		_ = p.ws.Close()
	}
}

// The plan's codecs: what its tracks send, what it asks Rust to send, and what Rust reflects.
func (p *Peer) planCodecs() map[string]bool {
	c := map[string]bool{}
	for _, s := range p.plan.Steps {
		switch s.str("op") {
		case "track":
			c[strings.ToLower(s.str("codec"))] = true
		case "request-offer":
			for _, t := range s.strs("tracks") {
				c[strings.ToLower(t)] = true
			}
		}
	}
	if v, ok := p.plan.Scenario["video"].(string); ok {
		c[strings.ToLower(v)] = true
	}
	if a, ok := p.plan.Scenario["audio"].(bool); ok && a {
		c["opus"] = true
	}
	return c
}

var videoFeedback = []webrtc.RTCPFeedback{
	{Type: "goog-remb"}, {Type: "ccm", Parameter: "fir"}, {Type: "nack"}, {Type: "nack", Parameter: "pli"},
	{Type: "transport-cc"},
}

// The media engine: the plan's codecs only (each video codec with its RTX, RFC 4588), so every
// offer and answer names the codec the cell is about.
func (p *Peer) mediaEngine() (*webrtc.MediaEngine, error) {
	m := &webrtc.MediaEngine{}
	codecs := p.planCodecs()
	if len(codecs) == 0 {
		codecs = map[string]bool{"vp8": true, "opus": true}
	}
	if !codecs["opus"] {
		codecs["opus"] = true
	}
	reg := func(mime string, fmtp string, pt uint8, kind webrtc.RTPCodecType, rtx bool) error {
		capab := webrtc.RTPCodecCapability{MimeType: mime, ClockRate: 90000, SDPFmtpLine: fmtp}
		if kind == webrtc.RTPCodecTypeAudio {
			capab = webrtc.RTPCodecCapability{MimeType: mime, ClockRate: 48000, Channels: 2, SDPFmtpLine: fmtp}
		} else {
			capab.RTCPFeedback = videoFeedback
		}
		if err := m.RegisterCodec(webrtc.RTPCodecParameters{RTPCodecCapability: capab, PayloadType: webrtc.PayloadType(pt)}, kind); err != nil {
			return err
		}
		if rtx {
			return m.RegisterCodec(webrtc.RTPCodecParameters{
				RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeRTX, ClockRate: 90000, SDPFmtpLine: fmt.Sprintf("apt=%d", pt)},
				PayloadType:        webrtc.PayloadType(pt + 1),
			}, kind)
		}
		return nil
	}
	if err := reg(webrtc.MimeTypeOpus, "minptime=10;useinbandfec=1", 111, webrtc.RTPCodecTypeAudio, false); err != nil {
		return nil, err
	}
	video := false
	if codecs["vp8"] {
		video = true
		if err := reg(webrtc.MimeTypeVP8, "", 96, webrtc.RTPCodecTypeVideo, true); err != nil {
			return nil, err
		}
	}
	if codecs["vp9"] {
		video = true
		if err := reg(webrtc.MimeTypeVP9, "profile-id=0", 98, webrtc.RTPCodecTypeVideo, true); err != nil {
			return nil, err
		}
	}
	if codecs["h264"] {
		video = true
		if err := reg(webrtc.MimeTypeH264, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", 102, webrtc.RTPCodecTypeVideo, true); err != nil {
			return nil, err
		}
	}
	if !video {
		if err := reg(webrtc.MimeTypeVP8, "", 96, webrtc.RTPCodecTypeVideo, true); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (p *Peer) setup() error {
	if p.plan.Config.CAFile != "" {
		// Go reads the system roots from SSL_CERT_FILE: the TURN-over-TLS server's CA.
		_ = os.Setenv("SSL_CERT_FILE", p.plan.Config.CAFile)
	}
	m, err := p.mediaEngine()
	if err != nil {
		return err
	}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(m, ir); err != nil {
		return err
	}
	// Sequence numbers for transport-wide congestion control on what this side sends, so Rust
	// has something to send feedback about.
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(m, ir); err != nil {
		return err
	}
	p.res.TWCCSent = true
	se := webrtc.SettingEngine{}
	networks := []webrtc.NetworkType{webrtc.NetworkTypeUDP4}
	if p.plan.Config.TCP {
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return err
		}
		se.SetICETCPMux(webrtc.NewICETCPMux(nil, l, 16))
		networks = append(networks, webrtc.NetworkTypeTCP4)
	}
	se.SetNetworkTypes(networks)
	if p.plan.Config.MDNS {
		se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryAndGather)
	} else {
		se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryOnly)
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(ir), webrtc.WithSettingEngine(se))
	cfg := webrtc.Configuration{}
	for _, s := range p.plan.Config.ICEServers {
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: s.URLs, Username: s.Username, Credential: s.Credential})
	}
	if p.plan.Config.ICETransportPolicy == "relay" {
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	switch p.plan.Config.BundlePolicy {
	case "max-compat":
		cfg.BundlePolicy = webrtc.BundlePolicyMaxCompat
	case "max-bundle":
		cfg.BundlePolicy = webrtc.BundlePolicyMaxBundle
	}
	pc, err := api.NewPeerConnection(cfg)
	if err != nil {
		return err
	}
	p.pc = pc
	pc.OnICECandidate(func(c *webrtc.ICECandidate) { p.cands <- c })
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) { log.Printf("connection state %s", s) })
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		label := dc.Label()
		p.mu.Lock()
		if _, ok := p.dcs[label]; !ok {
			p.dcs[label] = dc
		}
		p.mu.Unlock()
		p.onMessages(dc, true)
	})
	pc.OnTrack(func(t *webrtc.TrackRemote, r *webrtc.RTPReceiver) {
		kind := t.Kind().String()
		p.mu.Lock()
		if t.Kind() == webrtc.RTPCodecTypeVideo {
			p.remoteVideo = append(p.remoteVideo, uint32(t.SSRC()))
		}
		p.mu.Unlock()
		go p.readRTCP(r.ReadRTCP)
		go func() {
			for {
				pkt, _, err := t.ReadRTP()
				if err != nil {
					return
				}
				p.mu.Lock()
				c := p.res.RTP[kind]
				if c == nil {
					c = &Count{}
					p.res.RTP[kind] = c
				}
				c.Packets++
				c.Bytes += len(pkt.Payload)
				c.Codec = strings.ToLower(t.Codec().MimeType)
				cv := p.cov[pkt.SSRC]
				if cv == nil {
					cv = &coverage{kind: kind, last: -1, seen: map[uint64]bool{}}
					p.cov[pkt.SSRC] = cv
				}
				cv.add(pkt.SequenceNumber)
				p.mu.Unlock()
			}
		}()
	})
	ws, err := websocket.Dial(p.plan.WS, "", "http://localhost/")
	if err != nil {
		return fmt.Errorf("websocket %s: %w", p.plan.WS, err)
	}
	ws.MaxPayloadBytes = 64 << 20
	p.ws = ws
	go func() {
		for {
			var text string
			if err := websocket.Message.Receive(ws, &text); err != nil {
				close(p.inbox)
				return
			}
			var m map[string]any
			if json.Unmarshal([]byte(text), &m) == nil {
				p.inbox <- m
			}
		}
	}()
	return nil
}

func rtcpName(pk rtcp.Packet) string {
	switch pk.(type) {
	case *rtcp.SenderReport:
		return "sr"
	case *rtcp.ReceiverReport:
		return "rr"
	case *rtcp.SourceDescription:
		return "sdes"
	case *rtcp.Goodbye:
		return "bye"
	case *rtcp.TransportLayerNack:
		return "nack"
	case *rtcp.TransportLayerCC:
		return "twcc"
	case *rtcp.CCFeedbackReport:
		return "ccfb"
	case *rtcp.PictureLossIndication:
		return "pli"
	case *rtcp.FullIntraRequest:
		return "fir"
	case *rtcp.ReceiverEstimatedMaximumBitrate:
		return "remb"
	case *rtcp.ExtendedReport:
		return "xr"
	default:
		return strings.TrimPrefix(fmt.Sprintf("%T", pk), "*rtcp.")
	}
}

func (p *Peer) readRTCP(read func() ([]rtcp.Packet, interceptor.Attributes, error)) {
	for {
		pkts, _, err := read()
		if err != nil {
			return
		}
		p.mu.Lock()
		for _, pk := range pkts {
			p.res.RTCP[rtcpName(pk)]++
		}
		p.mu.Unlock()
	}
}

func (p *Peer) onMessages(dc *webrtc.DataChannel, remote bool) {
	label := dc.Label()
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if remote {
			if _, ok := p.res.RemoteChannels[label]; !ok {
				p.res.RemoteChannels[label] = string(msg.Data)
			}
		}
		e := p.res.DataChannels[label]
		if e == nil {
			e = &Echo{Got: []any{}, Sizes: []int{}}
			p.res.DataChannels[label] = e
		}
		if msg.IsString {
			e.Got = append(e.Got, string(msg.Data))
		} else if len(msg.Data) >= 4 {
			e.Got = append(e.Got, binary.BigEndian.Uint32(msg.Data[:4]))
		} else {
			e.Got = append(e.Got, -1)
		}
		e.Sizes = append(e.Sizes, len(msg.Data))
	})
}

// ---- signalling ----

func (p *Peer) send(m map[string]any) error {
	t := m["type"]
	if (t == "offer" || t == "request-offer") && !p.sentScenario {
		sc := p.plan.Scenario
		if sc == nil {
			sc = map[string]any{}
		}
		m["scenario"] = sc
		p.sentScenario = true
	}
	b, _ := json.Marshal(m)
	return websocket.Message.Send(p.ws, string(b))
}

func (p *Peer) record(dir, typ, sdp string) {
	p.mu.Lock()
	p.res.Descriptions = append(p.res.Descriptions, [3]string{dir, typ, sdp})
	p.mu.Unlock()
}

var bundleLine = regexp.MustCompile(`(?m)^a=group:BUNDLE[^\r\n]*\r?\n`)

func munge(kind, sdp string) string {
	if kind == "strip-bundle" {
		return bundleLine.ReplaceAllString(sdp, "")
	}
	return sdp
}

var ufragLine = regexp.MustCompile(`(?m)^a=ice-ufrag:(\S+)`)
var midLine = regexp.MustCompile(`(?m)^a=mid:(\S+)`)

func ufragOf(sdp string) string {
	if m := ufragLine.FindStringSubmatch(sdp); m != nil {
		return m[1]
	}
	return ""
}

// Sends a description, then the candidates held for it (RFC 8838 4: a candidate follows the
// description it belongs to).
func (p *Peer) sendDescription(typ, sdp string) error {
	p.record("sent", typ, sdp)
	if err := p.send(map[string]any{"type": typ, "sdp": sdp}); err != nil {
		return err
	}
	p.lastSentSDP = sdp
	if typ == "answer" {
		p.answersSent++
	}
	return p.flush()
}

func (p *Peer) flush() error {
	if !p.plan.Config.Trickle || p.lastSentSDP == "" {
		p.held = nil
		return nil
	}
	ufrag := ufragOf(p.lastSentSDP)
	keep := []webrtc.ICECandidateInit{}
	for _, c := range p.held {
		if c.UsernameFragment != nil && *c.UsernameFragment != ufrag {
			// A later generation's candidate waits for its description; an earlier one's is
			// dropped once a later description went out.
			if p.pc.LocalDescription() != nil && ufragOf(p.pc.LocalDescription().SDP) == *c.UsernameFragment {
				keep = append(keep, c)
			}
			continue
		}
		if err := p.send(map[string]any{"type": "candidate", "candidate": c}); err != nil {
			return err
		}
		p.trickled()
	}
	p.held = keep
	return nil
}

func (p *Peer) trickled() {
	p.mu.Lock()
	p.res.Trickled++
	p.mu.Unlock()
}

func (p *Peer) onCandidate(c *webrtc.ICECandidate) error {
	if c == nil {
		p.gatherDone = true
		return nil
	}
	init := c.ToJSON()
	p.mu.Lock()
	p.res.LocalCandidates = append(p.res.LocalCandidates, init.Candidate)
	p.mu.Unlock()
	ld := p.pc.LocalDescription()
	if ld != nil {
		// The first media section of the description (the BUNDLE-tag), and its ufrag.
		if init.SDPMid == nil || *init.SDPMid == "" {
			if m := midLine.FindStringSubmatch(ld.SDP); m != nil {
				mid := m[1]
				init.SDPMid = &mid
			}
			idx := uint16(0)
			init.SDPMLineIndex = &idx
		}
		if init.UsernameFragment == nil || *init.UsernameFragment == "" {
			u := ufragOf(ld.SDP)
			init.UsernameFragment = &u
		}
	}
	p.held = append(p.held, init)
	return p.flush()
}

func (p *Peer) handle(m map[string]any) error {
	switch m["type"] {
	case "answer":
		sdp, _ := m["sdp"].(string)
		p.record("received", "answer", sdp)
		if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}); err != nil {
			return fmt.Errorf("applying Rust's answer: %w", err)
		}
		p.answersGot++
	case "offer":
		sdp, _ := m["sdp"].(string)
		p.mu.Lock()
		p.res.RemoteOffers++
		p.mu.Unlock()
		if p.impolite && p.pc.SignalingState() != webrtc.SignalingStateStable {
			p.mu.Lock()
			p.res.IgnoredOffers++
			p.mu.Unlock()
			p.record("ignored", "offer", sdp)
			return nil
		}
		sdp = munge(p.mungeRemote, sdp)
		p.mungeRemote = ""
		p.record("received", "offer", sdp)
		if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
			return fmt.Errorf("applying Rust's offer: %w", err)
		}
		answer, err := p.pc.CreateAnswer(nil)
		if err != nil {
			return fmt.Errorf("creating the answer: %w", err)
		}
		if err := p.setLocal(answer); err != nil {
			return err
		}
		return p.sendDescription("answer", p.pc.LocalDescription().SDP)
	case "candidate":
		c, ok := m["candidate"].(map[string]any)
		if !ok || c["candidate"] == nil || c["candidate"] == "" {
			return nil
		}
		b, _ := json.Marshal(c)
		var init webrtc.ICECandidateInit
		if err := json.Unmarshal(b, &init); err != nil {
			return err
		}
		return p.pc.AddICECandidate(init)
	case "report":
		p.mu.Lock()
		p.res.Rust = m
		p.reports++
		p.mu.Unlock()
	case "error":
		p.mu.Lock()
		p.res.RustErrors = append(p.res.RustErrors, fmt.Sprint(m["error"]))
		p.mu.Unlock()
	}
	return nil
}

// Applies a local description; without trickle, waits for gathering to finish so the
// description carries every candidate.
func (p *Peer) setLocal(d webrtc.SessionDescription) error {
	var done <-chan struct{}
	if !p.plan.Config.Trickle {
		done = webrtc.GatheringCompletePromise(p.pc)
	}
	if err := p.pc.SetLocalDescription(d); err != nil {
		return fmt.Errorf("applying the local %s: %w", d.Type, err)
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			return errors.New("ICE gathering did not complete in 15 s")
		}
	}
	return nil
}

// Handles signalling and candidates until `cond` holds (checked after each event and every
// 50 ms), failing at `until`.
func (p *Peer) pump(until time.Time, what string, cond func() (bool, error)) error {
	if until.After(p.deadline) {
		until = p.deadline
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		ok, err := cond()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if time.Now().After(until) {
			return fmt.Errorf("timed out waiting for %s", what)
		}
		select {
		case m, open := <-p.inbox:
			if !open {
				return fmt.Errorf("the signalling connection closed while waiting for %s", what)
			}
			if err := p.handle(m); err != nil {
				return err
			}
		case c := <-p.cands:
			if err := p.onCandidate(c); err != nil {
				return err
			}
		case <-tick.C:
		}
	}
}

func ms(s Step, def int) time.Time {
	return time.Now().Add(time.Duration(s.num("ms", def)) * time.Millisecond)
}

// ---- media sources: the environment's fixtures, looped ----

func (p *Peer) fixture(name string) string { return p.plan.Media + "/" + name }

func ptr[T any](v T) *T { return &v }

func (p *Peer) stream(stop chan struct{}, codec string, tracks []*webrtc.TrackLocalStaticSample, kind string) {
	write := func(data []byte, d time.Duration) bool {
		for _, t := range tracks {
			_ = t.WriteSample(media.Sample{Data: data, Duration: d})
		}
		p.mu.Lock()
		c := p.res.RTPSent[kind]
		if c == nil {
			c = &Count{}
			p.res.RTPSent[kind] = c
		}
		c.Packets++
		c.Bytes += len(data)
		p.mu.Unlock()
		select {
		case <-stop:
			return false
		case <-time.After(d):
			return true
		}
	}
	for {
		var err error
		switch codec {
		case "vp8", "vp9":
			err = p.streamIVF(map[string]string{"vp8": "vp8.ivf", "vp9": "vp9.ivf"}[codec], write)
		case "h264":
			err = p.streamH264(write)
		default:
			err = p.streamOgg(write)
		}
		if errors.Is(err, errStopped) {
			return
		}
		if err != nil {
			log.Printf("%s source: %v", codec, err)
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
		}
	}
}

var errStopped = errors.New("stopped")

func (p *Peer) streamIVF(file string, write func([]byte, time.Duration) bool) error {
	f, err := os.Open(p.fixture(file))
	if err != nil {
		return err
	}
	defer f.Close()
	r, _, err := ivfreader.NewWith(f)
	if err != nil {
		return err
	}
	for {
		frame, _, err := r.ParseNextFrame()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !write(frame, 33*time.Millisecond) {
			return errStopped
		}
	}
}

// H.264 access units (the fixture has one slice per picture): the parameter sets and the
// slice of a picture go as one Annex B sample.
func (p *Peer) streamH264(write func([]byte, time.Duration) bool) error {
	f, err := os.Open(p.fixture("h264.h264"))
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := h264reader.NewReader(f)
	if err != nil {
		return err
	}
	var au []byte
	for {
		nal, err := r.NextNAL()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		au = append(au, 0, 0, 0, 1)
		au = append(au, nal.Data...)
		if nal.UnitType == h264reader.NalUnitTypeCodedSliceIdr || nal.UnitType == h264reader.NalUnitTypeCodedSliceNonIdr {
			if !write(au, 33*time.Millisecond) {
				return errStopped
			}
			au = nil
		}
	}
}

// Opus packets, one per Ogg page in the fixture (opus.ogg), timed by the granule positions.
func (p *Peer) streamOgg(write func([]byte, time.Duration) bool) error {
	f, err := os.Open(p.fixture("opus.ogg"))
	if err != nil {
		return err
	}
	defer f.Close()
	r, _, err := oggreader.NewWith(f)
	if err != nil {
		return err
	}
	var last uint64
	for {
		page, h, err := r.ParseNextPage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if len(page) >= 8 && (string(page[:8]) == "OpusHead" || string(page[:8]) == "OpusTags") {
			continue
		}
		samples := h.GranulePosition - last
		last = h.GranulePosition
		if samples == 0 || samples > 48000 {
			samples = 960
		}
		if !write(page, time.Duration(samples)*time.Second/48000) {
			return errStopped
		}
	}
}

var mimes = map[string]string{
	"opus": webrtc.MimeTypeOpus, "vp8": webrtc.MimeTypeVP8, "vp9": webrtc.MimeTypeVP9, "h264": webrtc.MimeTypeH264,
}

func (p *Peer) addTrack(s Step) error {
	kind, codec := s.str("kind"), strings.ToLower(s.str("codec"))
	mime, ok := mimes[codec]
	if !ok {
		return fmt.Errorf("no codec %q", codec)
	}
	rids := s.strs("simulcast")
	var tracks []*webrtc.TrackLocalStaticSample
	capab := webrtc.RTPCodecCapability{MimeType: mime}
	if len(rids) == 0 {
		t, err := webrtc.NewTrackLocalStaticSample(capab, kind, "pion")
		if err != nil {
			return err
		}
		tracks = append(tracks, t)
	} else {
		for _, rid := range rids {
			t, err := webrtc.NewTrackLocalStaticSample(capab, kind, "pion", webrtc.WithRTPStreamID(rid))
			if err != nil {
				return err
			}
			tracks = append(tracks, t)
		}
	}
	sender, err := p.pc.AddTrack(tracks[0])
	if err != nil {
		return err
	}
	for _, t := range tracks[1:] {
		if err := sender.AddEncoding(t); err != nil {
			return err
		}
	}
	if enc := sender.GetParameters().Encodings; len(enc) > 0 {
		p.localSSRC = uint32(enc[0].SSRC)
	}
	go p.readRTCP(sender.ReadRTCP)
	stop := make(chan struct{})
	p.senders[kind] = sender
	p.stops[kind] = stop
	go p.stream(stop, codec, tracks, kind)
	return nil
}

// The UDP port of Rust's host candidate in its last description (what netem filters on).
var hostCandidate = regexp.MustCompile(`(?mi)^a=candidate:\S+ \d+ udp \d+ \S+ (\d+) typ host`)

func (p *Peer) rustPort() int {
	rd := p.pc.RemoteDescription()
	if rd == nil {
		return 0
	}
	m := hostCandidate.FindStringSubmatch(rd.SDP)
	if m == nil {
		return 0
	}
	var port int
	fmt.Sscan(m[1], &port)
	return port
}

func (p *Peer) control(ev map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(ev)
	fmt.Println(string(b))
	line, err := p.stdin.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("no answer from the runner to %v: %w", ev["event"], err)
	}
	var reply map[string]any
	if err := json.Unmarshal([]byte(line), &reply); err != nil {
		return nil, err
	}
	if ok, _ := reply["ok"].(bool); !ok {
		return reply, fmt.Errorf("the runner refused %v: %v", ev["event"], reply["error"])
	}
	return reply, nil
}

func (p *Peer) connectedCond() (bool, error) {
	switch p.pc.ConnectionState() {
	case webrtc.PeerConnectionStateConnected:
		return true, nil
	case webrtc.PeerConnectionStateFailed:
		return false, errors.New("connection failed")
	}
	return false, nil
}

func (p *Peer) rtpCount(kind string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.res.RTP[kind]; c != nil {
		return c.Packets
	}
	return 0
}

func (p *Peer) rustRTP(kind string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	if rtp, ok := p.res.Rust["rtp"].(map[string]any); ok {
		for k, v := range rtp {
			if strings.HasPrefix(k, kind+":") {
				if f, ok := v.(float64); ok {
					n += int(f)
				}
			}
		}
	}
	return n
}

func (p *Peer) report(until time.Time) error {
	p.mu.Lock()
	n := p.reports
	p.mu.Unlock()
	if err := p.send(map[string]any{"type": "report"}); err != nil {
		return err
	}
	return p.pump(until, "Rust's report", func() (bool, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.reports > n, nil
	})
}

func (p *Peer) offer(s Step) error {
	var opts *webrtc.OfferOptions
	if s.boolean("iceRestart") {
		opts = &webrtc.OfferOptions{ICERestart: true}
	}
	o, err := p.pc.CreateOffer(opts)
	if err != nil {
		return err
	}
	if err := p.setLocal(o); err != nil {
		return err
	}
	local := p.pc.LocalDescription().SDP
	p.record("local", "offer", local)
	got := p.answersGot
	if err := p.sendDescription("offer", munge(s.str("munge"), local)); err != nil {
		return err
	}
	return p.pump(ms(s, 15000), "the answer", func() (bool, error) {
		return p.answersGot > got && p.pc.SignalingState() == webrtc.SignalingStateStable, nil
	})
}

func (p *Peer) step(s Step) (StepResult, error) {
	r := StepResult{Op: s.str("op")}
	var err error
	switch r.Op {
	case "dc":
		init := &webrtc.DataChannelInit{}
		if s.has("ordered") {
			init.Ordered = ptr(s.boolean("ordered"))
		}
		if s.has("maxRetransmits") {
			init.MaxRetransmits = ptr(uint16(s.num("maxRetransmits", 0)))
		}
		if s.has("maxPacketLifeTime") {
			init.MaxPacketLifeTime = ptr(uint16(s.num("maxPacketLifeTime", 0)))
		}
		if s.has("negotiated") {
			init.Negotiated = ptr(true)
			init.ID = ptr(uint16(s.num("negotiated", 0)))
		}
		var dc *webrtc.DataChannel
		dc, err = p.pc.CreateDataChannel(s.str("label"), init)
		if err == nil {
			p.mu.Lock()
			p.dcs[s.str("label")] = dc
			p.mu.Unlock()
			p.onMessages(dc, false)
		}
	case "track":
		err = p.addTrack(s)
	case "transceiver":
		dir := webrtc.NewRTPTransceiverDirection(s.str("direction"))
		kind := webrtc.NewRTPCodecType(s.str("kind"))
		_, err = p.pc.AddTransceiverFromKind(kind, webrtc.RTPTransceiverInit{Direction: dir})
	case "remove-track":
		kind := s.str("kind")
		if sender := p.senders[kind]; sender != nil {
			err = p.pc.RemoveTrack(sender)
			close(p.stops[kind])
			delete(p.senders, kind)
		} else {
			err = fmt.Errorf("no %s track to remove", kind)
		}
	case "offer":
		err = p.offer(s)
	case "request-offer":
		m := map[string]any{"type": "request-offer"}
		if t := s.strs("tracks"); len(t) > 0 {
			m["tracks"] = t
		}
		if s.boolean("iceRestart") {
			m["ice_restart"] = true
		}
		p.mungeRemote = s.str("munge")
		before := p.answersSent
		if err = p.send(m); err == nil {
			err = p.pump(ms(s, 15000), "Rust's offer, answered", func() (bool, error) {
				return p.answersSent > before && p.pc.SignalingState() == webrtc.SignalingStateStable, nil
			})
		}
	case "connected":
		err = p.pump(ms(s, 30000), "the connection", p.connectedCond)
	case "echo":
		err = p.echo(s)
	case "await-channel":
		label := s.str("label")
		err = p.pump(ms(s, 15000), "channel "+label+" and its first message", func() (bool, error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			_, ok := p.res.RemoteChannels[label]
			return ok, nil
		})
	case "await-rtp":
		kind := s.str("kind")
		want := s.num("packets", 0)
		if s.has("more") {
			want = p.rtpCount(kind) + s.num("more", 0)
		}
		err = p.pump(ms(s, 20000), fmt.Sprintf("%d %s packets from Rust", want, kind), func() (bool, error) {
			return p.rtpCount(kind) >= want, nil
		})
	case "await-rust-rtp":
		kind, want := s.str("kind"), s.num("packets", 0)
		until := ms(s, 20000)
		for err == nil && p.rustRTP(kind) < want {
			if time.Now().After(until) {
				err = fmt.Errorf("Rust has %d of %d %s packets", p.rustRTP(kind), want, kind)
				break
			}
			if err = p.report(until.Add(5 * time.Second)); err == nil {
				err = p.pump(time.Now().Add(300*time.Millisecond), "", func() (bool, error) { return false, nil })
				if err != nil && strings.HasPrefix(err.Error(), "timed out") {
					err = nil
				}
			}
		}
	case "rtcp":
		err = p.feedback(s.strs("types"))
	case "impair":
		port := p.rustPort()
		if _, err = p.control(map[string]any{"event": "impair", "direction": s.str("direction"), "rustPort": port}); err == nil {
			err = p.wait(s.num("ms", 10000))
			if _, e := p.control(map[string]any{"event": "unimpair"}); err == nil {
				err = e
			}
		}
	case "rollback":
		var o webrtc.SessionDescription
		if o, err = p.pc.CreateOffer(nil); err == nil {
			if err = p.pc.SetLocalDescription(o); err == nil {
				p.record("local", "offer", p.pc.LocalDescription().SDP)
				err = p.pc.SetLocalDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeRollback})
			}
		}
		r.SignalingState = p.pc.SignalingState().String()
	case "glare":
		err = p.glare(s)
	case "wait":
		err = p.wait(s.num("ms", 1000))
	case "report":
		err = p.report(time.Now().Add(5 * time.Second))
	default:
		err = fmt.Errorf("unknown step %q", r.Op)
	}
	return r, err
}

func (p *Peer) wait(d int) error {
	err := p.pump(time.Now().Add(time.Duration(d)*time.Millisecond), "", func() (bool, error) { return false, nil })
	if err != nil && strings.HasPrefix(err.Error(), "timed out") {
		return nil
	}
	return err
}

// Glare as the impolite peer: our offer is applied, Rust is asked for one (which we ignore
// while ours is outstanding), then ours goes out; Rust rolls back, answers, offers again.
func (p *Peer) glare(s Step) error {
	p.impolite = true
	o, err := p.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := p.setLocal(o); err != nil {
		return err
	}
	local := p.pc.LocalDescription().SDP
	p.record("local", "offer", local)
	if err := p.send(map[string]any{"type": "request-offer"}); err != nil {
		return err
	}
	got := p.answersGot
	if err := p.sendDescription("offer", local); err != nil {
		return err
	}
	return p.pump(ms(s, 20000), "the answer to our colliding offer", func() (bool, error) {
		return p.answersGot > got && p.pc.SignalingState() == webrtc.SignalingStateStable, nil
	})
}

func (p *Peer) feedback(types []string) error {
	p.mu.Lock()
	ssrcs := append([]uint32{}, p.remoteVideo...)
	p.mu.Unlock()
	if len(ssrcs) == 0 {
		return errors.New("no video from Rust to send feedback about")
	}
	var pkts []rtcp.Packet
	for _, ssrc := range ssrcs {
		for _, t := range types {
			switch t {
			case "pli":
				pkts = append(pkts, &rtcp.PictureLossIndication{SenderSSRC: p.localSSRC, MediaSSRC: ssrc})
			case "fir":
				pkts = append(pkts, &rtcp.FullIntraRequest{SenderSSRC: p.localSSRC, MediaSSRC: ssrc,
					FIR: []rtcp.FIREntry{{SSRC: ssrc, SequenceNumber: 1}}})
			}
		}
	}
	for i := 0; i < 3; i++ {
		if err := p.pc.WriteRTCP(pkts); err != nil {
			return err
		}
		p.mu.Lock()
		for _, t := range types {
			p.res.RTCPSent[t] += len(ssrcs)
		}
		p.mu.Unlock()
		if err := p.wait(200); err != nil {
			return err
		}
	}
	return nil
}

func (p *Peer) echo(s Step) error {
	label := s.str("label")
	count, size := s.num("count", 1), s.num("size", 0)
	until := ms(s, 20000)
	var dc *webrtc.DataChannel
	if err := p.pump(until, "channel "+label+" to open", func() (bool, error) {
		p.mu.Lock()
		dc = p.dcs[label]
		p.mu.Unlock()
		return dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen, nil
	}); err != nil {
		return err
	}
	p.mu.Lock()
	base := 0
	if e := p.res.DataChannels[label]; e != nil {
		base = len(e.Got)
	}
	p.mu.Unlock()
	for i := 0; i < count; i++ {
		var err error
		if size > 0 {
			b := make([]byte, size)
			for j := range b {
				b[j] = byte(i % 251)
			}
			binary.BigEndian.PutUint32(b[:4], uint32(i))
			err = dc.Send(b)
		} else {
			err = dc.SendText(fmt.Sprintf("msg-%d", i))
		}
		if err != nil {
			return fmt.Errorf("send %d on %s: %w", i, label, err)
		}
		for dc.BufferedAmount() > 1<<20 {
			if err := p.wait(5); err != nil {
				return err
			}
		}
	}
	return p.pump(until, fmt.Sprintf("%d echoed messages on %s", count, label), func() (bool, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		e := p.res.DataChannels[label]
		return e != nil && len(e.Got)-base >= count, nil
	})
}

func (p *Peer) run() error {
	if err := p.setup(); err != nil {
		return err
	}
	for i, s := range p.plan.Steps {
		start := time.Now()
		r, err := p.step(s)
		r.MS = time.Since(start).Milliseconds()
		r.OK = err == nil
		if err != nil {
			r.Error = err.Error()
		}
		p.mu.Lock()
		p.res.Steps = append(p.res.Steps, r)
		p.mu.Unlock()
		if err != nil {
			var na naError
			if errors.As(err, &na) {
				return err
			}
			return fmt.Errorf("step %d (%s): %w", i, r.Op, err)
		}
	}
	return nil
}

// What the stack negotiated, from its W3C stats: the selected pair, DTLS and SCTP.
func (p *Peer) collect() {
	report := p.pc.GetStats()
	var pair *webrtc.ICECandidatePairStats
	var transport *webrtc.TransportStats
	for _, s := range report {
		switch v := s.(type) {
		case webrtc.TransportStats:
			t := v
			if transport == nil || t.DTLSState == webrtc.DTLSTransportStateConnected {
				transport = &t
			}
		case webrtc.ICECandidatePairStats:
			pp := v
			if pp.Nominated && pp.State == webrtc.StatsICECandidatePairStateSucceeded {
				pair = &pp
			}
		}
	}
	if transport != nil && transport.SelectedCandidatePairID != "" {
		if s, ok := report[transport.SelectedCandidatePairID].(webrtc.ICECandidatePairStats); ok {
			pair = &s
		}
	}
	cand := func(id string) map[string]any {
		c, ok := report[id].(webrtc.ICECandidateStats)
		if !ok {
			return nil
		}
		out := map[string]any{"candidateType": c.CandidateType.String(), "protocol": c.Protocol, "address": c.IP, "port": c.Port}
		if c.RelayProtocol != "" {
			out["relayProtocol"] = c.RelayProtocol
		} else {
			out["relayProtocol"] = nil
		}
		return out
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if pair != nil {
		p.res.SelectedPair = map[string]any{"local": cand(pair.LocalCandidateID), "remote": cand(pair.RemoteCandidateID)}
	}
	if transport != nil && transport.DTLSState == webrtc.DTLSTransportStateConnected {
		p.res.DTLS = map[string]any{
			"version": nilIfEmpty(transport.TLSVersion), "cipher": nilIfEmpty(transport.DTLSCipher),
			"srtpProfile": nilIfEmpty(transport.SRTPCipher), "role": nil,
		}
	}
	if t := p.pc.SCTP(); t != nil {
		p.res.SCTP = map[string]any{
			"maxMessageSize": t.GetCapabilities().MaxMessageSize, "maxChannels": t.MaxChannels(),
			"state": t.State().String(),
		}
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
