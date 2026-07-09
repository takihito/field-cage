module github.com/takihito/field-cage

go 1.25.0

require (
	github.com/cilium/ebpf v0.21.0
	// dnsmessage is the wire DNS parser the standard library's net package uses
	// internally; adopted for the attacker-controlled DNS-response parser
	// instead of a hand-rolled one. Pinned to the same version as the other
	// golang.org/x modules already in the graph.
	golang.org/x/net v0.46.0
	golang.org/x/sys v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)
