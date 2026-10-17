package api

import (
	"context"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/store"
)

// Only fixture construction/assertions need a complete test configuration.
// Exercise the real keyset pages, without restoring production list adapters.
func fixturePages[T any](fetch func(model.PageRequest) (model.Page[T], error)) ([]T, error) {
	items := make([]T, 0)
	request := model.PageRequest{Limit: store.MaximumPageLimit}
	for {
		page, err := fetch(request)
		if err != nil {
			return nil, err
		}
		items = append(items, page.Items...)
		if page.NextCursor == "" {
			return items, nil
		}
		request.Cursor = page.NextCursor
	}
}

func fixtureUpstreams(st *store.Store) ([]*model.Upstream, error) {
	return fixturePages(func(page model.PageRequest) (model.Page[*model.Upstream], error) {
		return st.ListUpstreamsPage(context.Background(), model.UpstreamFilter{PageRequest: page})
	})
}

func fixtureModelNames(st *store.Store) ([]*model.ModelName, error) {
	return fixturePages(func(page model.PageRequest) (model.Page[*model.ModelName], error) {
		return st.ListModelNamesPage(context.Background(), model.ModelNameFilter{PageRequest: page})
	})
}

func fixtureRoutes(st *store.Store, modelID int64) ([]*model.Route, error) {
	return fixturePages(func(page model.PageRequest) (model.Page[*model.Route], error) {
		return st.ListRoutesPage(context.Background(), model.RouteFilter{PageRequest: page, ModelNameID: modelID})
	})
}
