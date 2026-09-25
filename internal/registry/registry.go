package registry

import (
	"fmt"
	"sort"
	"strings"

	"gopoc/internal/model"
)

type Registry struct{ checks map[string]model.Checker }

func New() *Registry { return &Registry{checks: map[string]model.Checker{}} }

func (r *Registry) Register(c model.Checker) error {
	if c == nil || c.ID() == "" || c.Name() == "" || c.Metadata().ID != c.ID() {
		return fmt.Errorf("checker must have consistent, non-empty metadata")
	}
	id := strings.ToUpper(c.ID())
	if _, exists := r.checks[id]; exists {
		return fmt.Errorf("duplicate checker: %s", id)
	}
	r.checks[id] = c
	return nil
}

type Filter struct {
	IDs      []string
	Product  string
	Severity string
}

func (r *Registry) Select(filter Filter) ([]model.Checker, error) {
	ids := map[string]bool{}
	for _, id := range filter.IDs {
		id = strings.ToUpper(strings.TrimSpace(id))
		if _, ok := r.checks[id]; !ok {
			return nil, fmt.Errorf("unknown checker: %s", id)
		}
		ids[id] = true
	}
	selected := []model.Checker{}
	for id, c := range r.checks {
		meta := c.Metadata()
		if len(ids) != 0 && !ids[id] || filter.Product != "" && !strings.EqualFold(meta.Product, filter.Product) || filter.Severity != "" && !strings.EqualFold(meta.Severity, filter.Severity) {
			continue
		}
		selected = append(selected, c)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].ID() < selected[j].ID() })
	if len(selected) == 0 {
		return nil, fmt.Errorf("no checkers match the filters")
	}
	return selected, nil
}
