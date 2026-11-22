// Package zerotrust compiles device and user access requirements from
// Pomerium Policy Language and provides helpers for enforcing those
// requirements at runtime.
package zerotrust

import (
	"fmt"
	"io"
	"slices"

	"github.com/pomerium/pomerium/pkg/policy"
	"github.com/pomerium/pomerium/pkg/policy/parser"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

// PolicyCriterion is a criterion that contributed to a compiled policy.
type PolicyCriterion struct {
	Action    parser.Action
	Operator  string
	Criterion parser.Criterion
}

// UserRequirements summarizes positive user identity checks in a policy.
//
// The generated Rego remains the source of truth for evaluation. These fields
// are useful for auditing a policy and for rejecting configurations that do
// not include an expected user check. Required only means a user check is
// referenced by an allow rule; its and/or/not structure is preserved in Rego.
type UserRequirements struct {
	Required         bool
	AnyAuthenticated bool
	UserIDs          []string
	Emails           []string
	Domains          []string
	Groups           []string
}

// DeviceRequirements summarizes positive device checks in a policy.
//
// Required only means a device check is referenced by an allow rule; its
// and/or/not structure is preserved in Rego.
type DeviceRequirements struct {
	Required         bool
	TypeIDs          []string
	CredentialIDs    []string
	RequiresApproval bool
	ForbidsApproval  bool
}

// CompiledPolicy is a Pomerium access policy with its generated Rego and a
// normalized summary of the user and device constraints.
type CompiledPolicy struct {
	Rego               string
	Criteria           []PolicyCriterion
	UserRequirements   UserRequirements
	DeviceRequirements DeviceRequirements
}

// Compile compiles a Pomerium Policy Language policy into Rego and extracts
// user and device requirements from its allow rules.
func Compile(p *parser.Policy) (*CompiledPolicy, error) {
	if p == nil {
		return nil, fmt.Errorf("zero trust: policy is nil")
	}

	rego, err := policy.GenerateRegoFromPolicy(p)
	if err != nil {
		return nil, fmt.Errorf("zero trust: compile policy: %w", err)
	}

	compiled := &CompiledPolicy{Rego: rego}
	users := newStringSet()
	emails := newStringSet()
	domains := newStringSet()
	groups := newStringSet()
	deviceTypes := newStringSet()
	deviceCredentials := newStringSet()

	for _, rule := range p.Rules {
		for _, group := range []struct {
			operator string
			criteria []parser.Criterion
		}{
			{operator: "and", criteria: rule.And},
			{operator: "or", criteria: rule.Or},
			{operator: "not", criteria: rule.Not},
			{operator: "nor", criteria: rule.Nor},
		} {
			for _, criterion := range group.criteria {
				compiled.Criteria = append(compiled.Criteria, PolicyCriterion{
					Action:    rule.Action,
					Operator:  group.operator,
					Criterion: criterion,
				})

				// Negative operators and deny rules are not positive
				// requirements. They are still preserved in Criteria above
				// and enforced by the generated Rego.
				if rule.Action != parser.ActionAllow ||
					group.operator == "not" ||
					group.operator == "nor" {
					continue
				}

				switch criterion.Name {
				case "authenticated_user":
					compiled.UserRequirements.Required = true
					compiled.UserRequirements.AnyAuthenticated = true
				case "user":
					compiled.UserRequirements.Required = true
					users.addAll(stringMatcherValues(criterion.Data))
				case "email":
					compiled.UserRequirements.Required = true
					emails.addAll(stringMatcherValues(criterion.Data))
				case "domain":
					compiled.UserRequirements.Required = true
					domains.addAll(stringMatcherValues(criterion.Data))
				case "groups":
					compiled.UserRequirements.Required = true
					groups.addAll(stringListMatcherValues(criterion.Data))
				case "device":
					compiled.DeviceRequirements.Required = true
					typeID := webauthnutil.DefaultDeviceType
					if data, ok := criterion.Data.(parser.Object); ok {
						if value, ok := data["type"].(parser.String); ok {
							typeID = string(value)
						}
						if value, ok := data["is"].(parser.String); ok {
							deviceCredentials.add(string(value))
						}
						if value, ok := data["approved"].(parser.Boolean); ok {
							if bool(value) {
								compiled.DeviceRequirements.RequiresApproval = true
							} else {
								compiled.DeviceRequirements.ForbidsApproval = true
							}
						}
					}
					deviceTypes.add(typeID)
				}
			}
		}
	}

	compiled.UserRequirements.UserIDs = users.sorted()
	compiled.UserRequirements.Emails = emails.sorted()
	compiled.UserRequirements.Domains = domains.sorted()
	compiled.UserRequirements.Groups = groups.sorted()
	compiled.DeviceRequirements.TypeIDs = deviceTypes.sorted()
	compiled.DeviceRequirements.CredentialIDs = deviceCredentials.sorted()

	return compiled, nil
}

// CompileYAML parses and compiles a Pomerium Policy Language YAML document.
func CompileYAML(r io.Reader) (*CompiledPolicy, error) {
	p, err := parser.ParseYAML(r)
	if err != nil {
		return nil, fmt.Errorf("zero trust: parse policy: %w", err)
	}
	return Compile(p)
}

func stringMatcherValues(value parser.Value) []string {
	switch value := value.(type) {
	case parser.String:
		return []string{string(value)}
	case parser.Object:
		var values []string
		if v, ok := value["is"].(parser.String); ok {
			values = append(values, string(v))
		}
		if arr, ok := value["in"].(parser.Array); ok {
			for _, item := range arr {
				if v, ok := item.(parser.String); ok {
					values = append(values, string(v))
				}
			}
		}
		return values
	default:
		return nil
	}
}

func stringListMatcherValues(value parser.Value) []string {
	switch value := value.(type) {
	case parser.String:
		return []string{string(value)}
	case parser.Object:
		var values []string
		for _, key := range []string{"has", "is"} {
			if v, ok := value[key].(parser.String); ok {
				values = append(values, string(v))
			}
		}
		return values
	default:
		return nil
	}
}

type stringSet map[string]struct{}

func newStringSet() stringSet {
	return make(stringSet)
}

func (s stringSet) add(value string) {
	if value != "" {
		s[value] = struct{}{}
	}
}

func (s stringSet) addAll(values []string) {
	for _, value := range values {
		s.add(value)
	}
}

func (s stringSet) sorted() []string {
	if len(s) == 0 {
		return nil
	}
	values := make([]string, 0, len(s))
	for value := range s {
		values = append(values, value)
	}
	slices.Sort(values)
	return values
}
