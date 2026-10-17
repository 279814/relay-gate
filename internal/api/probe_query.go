package api

import (
	"net/http"
	"slices"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// probeListQuery parses the HTTP adapter's typed fields. Store still owns the
// filter fingerprint and parameterized query; no user-provided SQL is built.
type probeListQuery struct {
	r   *http.Request
	err error
}

func (q *probeListQuery) reject(name string) {
	if q.err == nil {
		q.err = model.WrapValidation("%s 筛选无效", name)
	}
}

func (q *probeListQuery) text(name string) string {
	values := q.r.URL.Query()[name]
	if len(values) > 1 {
		q.reject(name)
		return ""
	}
	if len(values) == 1 {
		return values[0]
	}
	return ""
}

func (q *probeListQuery) page() model.PageRequest {
	page, err := configPage(q.r)
	if err != nil && q.err == nil {
		q.err = err
	}
	page.Cursor = q.text("cursor")
	return page
}

func (q *probeListQuery) id(name string) int64 {
	id, err := configIDFilter(q.r, name)
	if err != nil && q.err == nil {
		q.err = err
	}
	return id
}

func (q *probeListQuery) boolean(name string) *bool {
	if _, present := q.r.URL.Query()[name]; !present {
		return nil
	}
	value := q.text(name)
	if value != "true" && value != "false" {
		q.reject(name)
		return nil
	}
	parsed := value == "true"
	return &parsed
}

func (q *probeListQuery) oneOf(name string, allowed ...string) string {
	value := q.text(name)
	if value != "" && !slices.Contains(allowed, value) {
		q.reject(name)
	}
	return value
}

func probeEnum[T ~string](q *probeListQuery, name string, valid func(T) bool) T {
	value := T(q.text(name))
	if value != "" && !valid(value) {
		q.reject(name)
	}
	return value
}

func (q *probeListQuery) day(name string) string {
	value := q.text(name)
	if value != "" {
		if _, err := time.Parse("2006-01-02", value); err != nil {
			q.reject(name)
		}
	}
	return value
}
