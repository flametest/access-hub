// Package dto defines the API request/response payloads. JSON field names are
// snake_case; IDs are UUID strings; timestamps are RFC3339.
package dto

// RoleSummary is the {code,name} pair used wherever a role list is embedded
// (workspace items, invitation previews).
type RoleSummary struct {
	Code string `json:"code"`
	Name string `json:"name"`
}
