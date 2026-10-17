package probe

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/279814/relay-gate/internal/model"
)

// DurableCostView reads the committed daily rollup. It has no mutable counters,
// JSON fallback or periodic writer, so a restart cannot change the totals.
type DurableCostView struct {
	source CostDailyReader
	now    func() time.Time
}

type CostDailyReader interface {
	ListProbeCostDaily(context.Context, model.ProbeCostFilter) (model.Page[*model.ProbeCostDaily], error)
}

type CostDailyStore interface {
	CostDailyReader
	RecordProbePiggybackSaving(context.Context, string, model.ProbeCostDaily) error
}

func NewDurableCostView(source CostDailyReader) *DurableCostView {
	return &DurableCostView{source: source, now: time.Now}
}

// StablePiggybackEventID uses its own cost-event kind, separate from execution
// rollup, so a repeated scheduling decision never charges another request.
func StablePiggybackEventID(dayUTC string, endpoint model.EndpointKind, routeID, upstreamID int64, token string) string {
	return fmt.Sprintf("piggyback_l2:%s:%s:%d:%d:%s", dayUTC, endpoint, routeID, upstreamID, token)
}

func (view *DurableCostView) Snapshot(ctx context.Context) (CostSnapshot, error) {
	if view == nil || view.source == nil {
		return CostSnapshot{}, errors.New("durable cost source unavailable")
	}
	day := view.now().UTC().Format("2006-01-02")
	result := CostSnapshot{Day: day, Routes: []RouteCost{}, Upstreams: []UpstreamCost{}}
	routes := map[int64]*RouteCost{}
	upstreams := map[int64]*UpstreamCost{}
	filter := model.ProbeCostFilter{DayFrom: day, DayTo: day, PageRequest: model.PageRequest{Limit: 200}}
	for {
		page, err := view.source.ListProbeCostDaily(ctx, filter)
		if err != nil {
			return CostSnapshot{}, err
		}
		for _, row := range page.Items {
			if row == nil || row.Trigger == model.TriggerRealTraffic {
				continue
			}
			if row.Endpoint == model.EndpointModels {
				up := upstreams[row.UpstreamID]
				if up == nil {
					up = &UpstreamCost{UpstreamID: row.UpstreamID}
					upstreams[row.UpstreamID] = up
				}
				up.L1Count += row.Requests
				up.L1Failed += row.Failed
				result.L1Count += row.Requests
				result.L1Failed += row.Failed
				continue
			}
			// count_tokens is not a model L2; its dedicated daily endpoint row
			// stays visible in the paginated cost query without inflating L2.
			if row.Endpoint == model.EndpointCountTokens {
				continue
			}
			route := routes[row.RouteID]
			if route == nil {
				route = &RouteCost{RouteID: row.RouteID}
				routes[row.RouteID] = route
			}
			tokens := row.EstimatedInputTokens + row.ObservedOutputTokens
			route.L2Count += row.Requests
			route.L2Failed += row.Failed
			route.EstTokens += tokens
			result.L2Count += row.Requests
			result.L2Failed += row.Failed
			result.EstTokens += tokens
		}
		if page.NextCursor == "" {
			break
		}
		filter.Cursor = page.NextCursor
	}
	for _, row := range routes {
		result.Routes = append(result.Routes, *row)
	}
	for _, row := range upstreams {
		result.Upstreams = append(result.Upstreams, *row)
	}
	sort.Slice(result.Routes, func(i, j int) bool { return result.Routes[i].RouteID < result.Routes[j].RouteID })
	sort.Slice(result.Upstreams, func(i, j int) bool { return result.Upstreams[i].UpstreamID < result.Upstreams[j].UpstreamID })
	return result, nil
}
