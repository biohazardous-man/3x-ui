package sub

import (
	"encoding/json"
	"testing"

	"github.com/mhsanaei/3x-ui/v3/database/model"
	"github.com/mhsanaei/3x-ui/v3/util/json_util"
)

func hasDirectOutOutbound(svc *SubJsonService) bool {
	for _, raw := range svc.defaultOutbounds {
		var outbound map[string]any
		if err := json.Unmarshal(raw, &outbound); err != nil {
			continue
		}
		if outbound["tag"] == "direct_out" {
			return true
		}
	}
	return false
}

func outboundSettings(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal outbound: %v", err)
	}
	settings, _ := parsed["settings"].(map[string]any)
	if settings == nil {
		t.Fatal("outbound has no settings")
	}
	return settings
}

func outboundObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("failed to unmarshal outbound: %v", err)
	}
	return parsed
}

func streamRaw(t *testing.T, svc *SubJsonService, raw string) json_util.RawMessage {
	t.Helper()
	data, err := json.Marshal(svc.streamData(raw))
	if err != nil {
		t.Fatalf("failed to marshal stream settings: %v", err)
	}
	return json_util.RawMessage(data)
}

func TestSubJsonServiceInjectsGlobalFinalMask(t *testing.T) {
	finalMask := `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}],"udp":[{"type":"noise","settings":{"noise":[{"type":"base64","packet":"SGVsbG8="}]}}],"quicParams":{"congestion":"bbr"}}`
	svc := NewSubJsonService("", "", "", finalMask, nil)

	if hasDirectOutOutbound(svc) {
		t.Fatal("direct_out outbound must never be emitted")
	}

	stream := svc.streamData(`{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`)
	if _, ok := stream["sockopt"]; ok {
		t.Fatal("legacy direct_out dialerProxy sockopt must never be set")
	}

	finalmask, _ := stream["finalmask"].(map[string]any)
	if finalmask == nil {
		t.Fatal("streamSettings is missing finalmask")
	}

	tcp, _ := finalmask["tcp"].([]any)
	if len(tcp) != 1 {
		t.Fatalf("tcp masks len = %d, want 1", len(tcp))
	}
	if first, _ := tcp[0].(map[string]any); first["type"] != "fragment" {
		t.Fatalf("tcp[0] type = %v, want fragment", first["type"])
	}

	udp, _ := finalmask["udp"].([]any)
	if len(udp) != 1 {
		t.Fatalf("udp masks len = %d, want 1", len(udp))
	}

	quic, _ := finalmask["quicParams"].(map[string]any)
	if quic == nil || quic["congestion"] != "bbr" {
		t.Fatalf("quicParams missing/wrong: %#v", finalmask["quicParams"])
	}
}

func TestSubJsonServiceMergesWithExistingFinalMask(t *testing.T) {
	finalMask := `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}`
	svc := NewSubJsonService("", "", "", finalMask, nil)

	stream := svc.streamData(`{
		"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}},
		"finalmask":{"tcp":[{"type":"sudoku"}]}
	}`)

	finalmask, _ := stream["finalmask"].(map[string]any)
	tcp, _ := finalmask["tcp"].([]any)
	if len(tcp) != 2 {
		t.Fatalf("tcp masks len = %d, want 2 (existing + global)", len(tcp))
	}
	a, _ := tcp[0].(map[string]any)
	b, _ := tcp[1].(map[string]any)
	if a["type"] != "sudoku" || b["type"] != "fragment" {
		t.Fatalf("tcp masks = %#v, want existing sudoku then global fragment", tcp)
	}
}

func TestSubJsonServiceNoFinalMaskWhenEmpty(t *testing.T) {
	svc := NewSubJsonService("", "", "", "", nil)
	stream := svc.streamData(`{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`)
	if _, ok := stream["finalmask"]; ok {
		t.Fatal("no finalmask should be emitted when subJsonFinalMask is empty")
	}
	if _, ok := stream["sockopt"]; ok {
		t.Fatal("legacy direct_out sockopt must never be set")
	}
}

func TestSubJsonServiceSkipsTopLevelMuxForXHTTP(t *testing.T) {
	svc := NewSubJsonService(`{"enabled":true,"concurrency":8}`, "", "", "", nil)
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1"}
	stream := streamRaw(t, svc, `{"network":"xhttp","security":"none","xhttpSettings":{"path":"/x"}}`)

	outbound := outboundObject(t, svc.genVless(inbound, stream, client))
	if _, ok := outbound["mux"]; ok {
		t.Fatalf("xhttp outbound must not emit top-level mux: %#v", outbound["mux"])
	}
}

func TestSubJsonServiceKeepsTopLevelMuxForNonXHTTP(t *testing.T) {
	svc := NewSubJsonService(`{"enabled":true,"concurrency":8}`, "", "", "", nil)
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1"}
	stream := streamRaw(t, svc, `{"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}`)

	outbound := outboundObject(t, svc.genVless(inbound, stream, client))
	mux, _ := outbound["mux"].(map[string]any)
	if mux == nil || mux["enabled"] != true || mux["concurrency"] != float64(8) {
		t.Fatalf("non-xhttp outbound must keep top-level mux: %#v", outbound["mux"])
	}
}

func TestSubJsonServiceInjectsGlobalXmuxForXHTTP(t *testing.T) {
	globalXmux := `{"maxConcurrency":"16-32","maxConnections":0,"cMaxReuseTimes":0,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","hKeepAlivePeriod":0}`
	svc := NewSubJsonService("", globalXmux, "", "", nil)

	stream := svc.streamData(`{"network":"xhttp","security":"none"}`)
	xhttp, _ := stream["xhttpSettings"].(map[string]any)
	if xhttp == nil {
		t.Fatal("xhttpSettings should be created when global XMUX is applied")
	}
	xmux, _ := xhttp["xmux"].(map[string]any)
	if xmux == nil || xmux["maxConcurrency"] != "16-32" || xmux["hMaxRequestTimes"] != "600-900" {
		t.Fatalf("global XMUX missing/wrong: %#v", xhttp["xmux"])
	}
}

func TestSubJsonServicePreservesExistingNonEmptyXmux(t *testing.T) {
	globalXmux := `{"maxConcurrency":"16-32","maxConnections":0,"hMaxRequestTimes":"600-900"}`
	svc := NewSubJsonService("", globalXmux, "", "", nil)

	stream := svc.streamData(`{"network":"xhttp","security":"none","xhttpSettings":{"xmux":{"maxConcurrency":"1","maxConnections":2}}}`)
	xhttp, _ := stream["xhttpSettings"].(map[string]any)
	xmux, _ := xhttp["xmux"].(map[string]any)
	if xmux["maxConcurrency"] != "1" || xmux["maxConnections"] != float64(2) {
		t.Fatalf("existing non-empty XMUX should be preserved: %#v", xmux)
	}
	if _, ok := xmux["hMaxRequestTimes"]; ok {
		t.Fatalf("global XMUX should not merge into existing non-empty XMUX: %#v", xmux)
	}
}

func TestSubJsonServiceFillsExistingEmptyXmux(t *testing.T) {
	globalXmux := `{"maxConcurrency":"16-32","maxConnections":0,"hMaxRequestTimes":"600-900"}`
	svc := NewSubJsonService("", globalXmux, "", "", nil)

	stream := svc.streamData(`{"network":"xhttp","security":"none","xhttpSettings":{"xmux":{}}}`)
	xhttp, _ := stream["xhttpSettings"].(map[string]any)
	xmux, _ := xhttp["xmux"].(map[string]any)
	if xmux == nil || xmux["maxConcurrency"] != "16-32" || xmux["hMaxRequestTimes"] != "600-900" {
		t.Fatalf("empty XMUX should be filled by global XMUX: %#v", xhttp["xmux"])
	}
}

func TestSubJsonServiceIgnoresMalformedOrEmptyGlobalXmux(t *testing.T) {
	cases := []struct {
		name string
		xmux string
	}{
		{name: "empty string", xmux: ""},
		{name: "empty object", xmux: "{}"},
		{name: "malformed", xmux: "{not-json"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewSubJsonService("", tc.xmux, "", "", nil)
			stream := svc.streamData(`{"network":"xhttp","security":"none","xhttpSettings":{"path":"/x"}}`)
			xhttp, _ := stream["xhttpSettings"].(map[string]any)
			if xhttp == nil || xhttp["path"] != "/x" {
				t.Fatalf("xhttpSettings should remain valid: %#v", stream["xhttpSettings"])
			}
			if _, ok := xhttp["xmux"]; ok {
				t.Fatalf("invalid/empty global XMUX should not add xmux: %#v", xhttp["xmux"])
			}
		})
	}
}

func TestSubJsonServiceVlessFlattened(t *testing.T) {
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VLESS, Settings: `{"encryption":"none"}`}
	client := model.Client{ID: "uuid-1", Flow: "xtls-rprx-vision"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", "", nil).genVless(inbound, nil, client))
	if _, ok := settings["vnext"]; ok {
		t.Fatal("vless outbound must not use vnext")
	}
	if settings["address"] != "1.2.3.4" || settings["id"] != "uuid-1" || settings["encryption"] != "none" || settings["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flat vless settings wrong: %#v", settings)
	}
}

func TestSubJsonServiceVmessFlattened(t *testing.T) {
	inbound := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.VMESS, Settings: `{}`}
	client := model.Client{ID: "uuid-2"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", "", nil).genVnext(inbound, nil, client))
	if _, ok := settings["vnext"]; ok {
		t.Fatal("vmess outbound must not use vnext")
	}
	if settings["id"] != "uuid-2" || settings["security"] != "auto" {
		t.Fatalf("flat vmess settings wrong: %#v", settings)
	}
}

func TestSubJsonServiceServerFlattened(t *testing.T) {
	trojan := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.Trojan, Settings: `{}`}
	client := model.Client{Password: "p4ss"}

	settings := outboundSettings(t, NewSubJsonService("", "", "", "", nil).genServer(trojan, nil, client))
	if _, ok := settings["servers"]; ok {
		t.Fatal("trojan outbound must not use servers array")
	}
	if settings["password"] != "p4ss" || settings["address"] != "1.2.3.4" {
		t.Fatalf("flat trojan settings wrong: %#v", settings)
	}

	ss := &model.Inbound{Listen: "1.2.3.4", Port: 443, Protocol: model.Shadowsocks, Settings: `{"method":"aes-256-gcm"}`}
	ssSettings := outboundSettings(t, NewSubJsonService("", "", "", "", nil).genServer(ss, nil, client))
	if ssSettings["method"] != "aes-256-gcm" {
		t.Fatalf("flat shadowsocks must carry method: %#v", ssSettings)
	}
}
