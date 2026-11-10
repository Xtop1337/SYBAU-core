// geo-fixtures writes geosite.dat and geoip.dat test files together with
// the matching decisions that Xray-core itself makes for them, so that the
// Rust loader in crates/sybau-route can be checked against the reference.
//
//	go run . ../../crates/sybau-route/tests/fixtures
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"google.golang.org/protobuf/proto"
)

func dom(t router.Domain_Type, v string, attrs ...string) *router.Domain {
	d := &router.Domain{Type: t, Value: v}
	for _, a := range attrs {
		d.Attribute = append(d.Attribute, &router.Domain_Attribute{Key: a, TypedValue: &router.Domain_Attribute_BoolValue{BoolValue: true}})
	}
	return d
}

func cidr(s string) *router.CIDR {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	ones, _ := n.Mask.Size()
	ip := n.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return &router.CIDR{Ip: ip, Prefix: uint32(ones)}
}

type siteCase struct {
	Site   string `json:"site"`
	Domain string `json:"domain"`
	Match  bool   `json:"match"`
}

type ipCase struct {
	Code    string `json:"code"`
	Reverse bool   `json:"reverse"`
	IP      string `json:"ip"`
	Match   bool   `json:"match"`
}

func filter(domains []*router.Domain, attrs []string) []*router.Domain {
	if len(attrs) == 0 {
		return domains
	}
	var out []*router.Domain
	for _, d := range domains {
		ok := true
		for _, want := range attrs {
			found := false
			for _, a := range d.Attribute {
				if a.Key == strings.ToLower(want) {
					found = true
				}
			}
			ok = ok && found
		}
		if ok {
			out = append(out, d)
		}
	}
	return out
}

func main() {
	out := os.Args[1]

	sites := []*router.GeoSite{
		{CountryCode: "TEST", Domain: []*router.Domain{
			dom(router.Domain_Full, "full.example.com"),
			dom(router.Domain_Domain, "suffix.example.org"),
			dom(router.Domain_Domain, "ads.example.net", "ads"),
			dom(router.Domain_Domain, "cn-ads.example.net", "ads", "cn"),
			dom(router.Domain_Plain, "keyword-hit"),
			dom(router.Domain_Regex, `^r[0-9]+\.regex\.test$`),
		}},
		{CountryCode: "EMPTY"},
	}
	// A large set to exercise the parser on realistic sizes.
	big := &router.GeoSite{CountryCode: "BIG"}
	for i := 0; i < 5000; i++ {
		big.Domain = append(big.Domain, dom(router.Domain_Domain, fmt.Sprintf("site%d.big.test", i)))
	}
	big.Domain = append(big.Domain, dom(router.Domain_Full, "exact.big.test"))
	sites = append(sites, big)
	writeProto(filepath.Join(out, "geosite.dat"), &router.GeoSiteList{Entry: sites})

	ips := []*router.GeoIP{
		{CountryCode: "RU", Cidr: []*router.CIDR{cidr("5.8.0.0/16"), cidr("77.88.0.0/18"), cidr("2a02:6b8::/32")}},
		{CountryCode: "TEST", Cidr: []*router.CIDR{cidr("10.0.0.0/8"), cidr("10.1.0.0/16"), cidr("192.0.2.1/32"), cidr("::1/128")}},
		{CountryCode: "PRIVATE", Cidr: []*router.CIDR{cidr("127.0.0.0/8"), cidr("192.168.0.0/16"), cidr("fc00::/7")}},
	}
	writeProto(filepath.Join(out, "geoip.dat"), &router.GeoIPList{Entry: ips})

	// Decisions of Xray's own matchers.
	var siteCases []siteCase
	queries := []string{
		"full.example.com", "www.full.example.com", "suffix.example.org", "a.b.suffix.example.org", "xsuffix.example.org",
		"ads.example.net", "x.ads.example.net", "cn-ads.example.net", "my-keyword-hit.io", "r12.regex.test", "rx.regex.test",
		"site0.big.test", "a.site4999.big.test", "site5000.big.test", "exact.big.test", "sub.exact.big.test", "unrelated.com",
	}
	for _, site := range []string{"TEST", "TEST@ads", "TEST@ads@cn", "EMPTY", "BIG"} {
		parts := strings.Split(site, "@")
		var domains []*router.Domain
		for _, s := range sites {
			if s.CountryCode == parts[0] {
				domains = filter(s.Domain, parts[1:])
			}
		}
		var matcher *router.DomainMatcher
		if len(domains) > 0 {
			// The matcher builder releases the slice it is given.
			own := make([]*router.Domain, len(domains))
			for i, d := range domains {
				own[i] = proto.Clone(d).(*router.Domain)
			}
			m, err := router.NewMphMatcherGroup(own)
			if err != nil {
				panic(err)
			}
			matcher = m
		}
		for _, q := range queries {
			siteCases = append(siteCases, siteCase{Site: strings.ToLower(site), Domain: q, Match: matcher != nil && matcher.ApplyDomain(q)})
		}
	}

	var ipCases []ipCase
	ipQueries := []string{"5.8.1.1", "5.9.0.0", "77.88.63.255", "77.88.64.0", "2a02:6b8::1", "2a02:6b9::1", "10.1.2.3",
		"11.0.0.0", "192.0.2.1", "192.0.2.2", "::1", "::2", "127.0.0.1", "192.168.5.5", "fd00::1", "8.8.8.8"}
	for _, code := range []string{"RU", "TEST", "PRIVATE"} {
		for _, reverse := range []bool{false, true} {
			var entry *router.GeoIP
			for _, e := range ips {
				if e.CountryCode == code {
					entry = &router.GeoIP{CountryCode: e.CountryCode, Cidr: e.Cidr, ReverseMatch: reverse}
				}
			}
			m, err := router.BuildOptimizedGeoIPMatcher(entry)
			if err != nil {
				panic(err)
			}
			for _, q := range ipQueries {
				ipCases = append(ipCases, ipCase{Code: strings.ToLower(code), Reverse: reverse, IP: q, Match: m.Match(net.ParseIP(q))})
			}
		}
	}
	writeJSON(filepath.Join(out, "xray-expectations.json"), map[string]any{"geosite": siteCases, "geoip": ipCases})
}

func writeProto(path string, m proto.Message) {
	b, err := proto.Marshal(m)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		panic(err)
	}
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}
