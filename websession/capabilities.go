package websession

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// The frozen record snapshot is used only to project the public capability DTO.
// It cannot direct a request to an arbitrary URL or enable an unavailable method.
//
//go:embed testdata/wire-records.json
var capabilityRecords []byte

func publicCapability(kind string, input map[string]any) (map[string]any, error) {
	var snapshot struct {
		Records []struct {
			Record     string   `json:"record"`
			Components []string `json:"components"`
			Nullable   []string `json:"nullable"`
		} `json:"records"`
	}
	if json.Unmarshal(capabilityRecords, &snapshot) != nil {
		return nil, invalid()
	}
	type schema struct {
		fields   []string
		nullable []string
	}
	schemas := map[string]schema{}
	for _, r := range snapshot.Records {
		schemas[r.Record] = schema{r.Components, r.Nullable}
	}
	var project func(string, map[string]any) (map[string]any, error)
	project = func(record string, source map[string]any) (map[string]any, error) {
		sch, ok := schemas[record]
		if !ok || source == nil {
			return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
		}
		out := map[string]any{}
		for _, component := range sch.fields {
			i := strings.LastIndex(component, " ")
			typ, name := component[:i], component[i+1:]
			v, found := source[name]
			if !found || (v == nil && !contains(sch.nullable, name)) {
				return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
			}
			if v == nil {
				out[name] = nil
				continue
			}
			baseType := typ
			list := strings.HasPrefix(typ, "List<")
			if list {
				baseType = strings.TrimSuffix(strings.TrimPrefix(typ, "List<"), ">")
			}
			if dot := strings.LastIndex(baseType, "."); dot >= 0 {
				baseType = baseType[dot+1:]
			}
			_, nested := schemas[baseType]
			check := func(value any) (any, error) {
				if nested {
					obj, ok := value.(map[string]any)
					if !ok {
						return nil, invalid()
					}
					return project(baseType, obj)
				}
				switch baseType {
				case "boolean":
					if _, ok := value.(bool); !ok {
						return nil, invalid()
					}
				case "int":
					if n, ok := value.(float64); !ok || n < 0 || n > 9007199254740991 || n != float64(int64(n)) {
						return nil, invalid()
					}
				default:
					str, ok := value.(string)
					if !ok || strings.TrimSpace(str) == "" {
						return nil, invalid()
					}
				}
				return value, nil
			}
			if list {
				values, ok := v.([]any)
				if !ok {
					return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
				}
				result := make([]any, 0, len(values))
				for _, value := range values {
					x, err := check(value)
					if err != nil {
						return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
					}
					result = append(result, x)
				}
				out[name] = result
			} else {
				x, err := check(v)
				if err != nil {
					return nil, failure(503, "IAM_RESPONSE_INVALID", ErrUnavailable)
				}
				out[name] = x
			}
		}
		return out, nil
	}
	name := "AuthMethodsPublicResponse"
	if kind == "auth-policy" {
		name = "AuthPolicyPublicResponse"
	}
	return project(name, input)
}
