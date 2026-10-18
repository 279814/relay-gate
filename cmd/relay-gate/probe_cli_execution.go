package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/configadmin"
	"github.com/279814/relay-gate/internal/health"
	"github.com/279814/relay-gate/internal/livecfg"
	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observationseq"
	"github.com/279814/relay-gate/internal/outbound"
	"github.com/279814/relay-gate/internal/probe"
	"github.com/279814/relay-gate/internal/proxy"
	"github.com/279814/relay-gate/internal/runstate"
	"github.com/279814/relay-gate/internal/sample"
	"github.com/279814/relay-gate/internal/store"
)

type cliProbeCandidate struct {
	alias      string
	modelAlias string
	up         *model.Upstream
	mn         *model.ModelName
	route      *model.Route
	endpoint   model.EndpointKind
}

func validateProbeCLIRows(rows []tsvRow) error {
	if len(rows) == 0 || len(rows) > 128 {
		return errCLIPrivateInput
	}
	for _, row := range rows {
		if row.Alias == "" || utf8.RuneCountInString(row.Alias) > 64 || model.APIKeyTooShortForOutbound(row.APIKey) || row.APIKey == "" {
			return errCLIPrivateInput
		}
		for _, character := range row.Alias {
			if !unicode.IsLetter(character) && !unicode.IsDigit(character) && !strings.ContainsRune("-_.", character) {
				return errCLIPrivateInput
			}
		}
		for _, other := range rows {
			if other.APIKey != "" && strings.Contains(row.Alias, other.APIKey) {
				return errCLIPrivateInput
			}
		}
	}
	return nil
}

// A CLI invocation owns an isolated real configuration and the same preparation,
// recorder and single-send executor as the service. No scheduler loop is started.
type probeCLIRunner struct {
	directory   string
	store       *store.Store
	source      *livecfg.Source
	executor    *probe.Executor
	preparer    *probe.Scheduler
	transports  *cliProbeTransports
	candidates  []cliProbeCandidate
	controls    map[string]cliPreparedControl
	now         func() time.Time
	controller  *runstate.Controller
	coordinator *probe.SyntheticCoordinator
}

type cliPreparedControl struct {
	fixture             *validatedControl
	versionID, revision int64
}

// Coordinator links cancellation from two parents. Its lease context does not
// expose the caller's Deadline, so retain the control's absolute deadline while
// keeping the real admission/release path (never an always-open replacement).
type cliSyntheticAdmission struct{ coordinator *probe.SyntheticCoordinator }

func (admission cliSyntheticAdmission) AcquireSynthetic(ctx context.Context, trigger model.ProbeTrigger) (context.Context, func(), error) {
	lease, release, err := admission.coordinator.AcquireSynthetic(ctx, trigger)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		bounded, cancel := context.WithDeadline(lease, deadline)
		return bounded, func() { cancel(); release() }, nil
	}
	return lease, release, nil
}

func candidateControlKey(candidate cliProbeCandidate) string {
	var routeID int64
	if candidate.route != nil {
		routeID = candidate.route.ID
	}
	return strconv.FormatInt(candidate.up.ID, 10) + "/" + strconv.FormatInt(routeID, 10) + "/" + string(candidate.endpoint)
}

type cliProbeTransports struct {
	manager  *outbound.Manager
	override http.RoundTripper
	trips    atomic.Int64
	hashKey  [32]byte
	last     *cliAttemptEvidence
}

func (transports *cliProbeTransports) RoundTripper(network outbound.NetworkConfig) (http.RoundTripper, error) {
	transport := transports.override
	if transport == nil {
		var err error
		transport, err = transports.manager.Transport(network)
		if err != nil {
			return nil, err
		}
	}
	return cliCountRoundTrip{RoundTripper: transport, owner: transports}, nil
}

type cliCountRoundTrip struct {
	http.RoundTripper
	owner *cliProbeTransports
}

func (transport cliCountRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	transport.owner.trips.Add(1)
	evidence := &cliAttemptEvidence{request: newCLIPrefixHash(transport.owner.hashKey[:], "relay-cli/request/v1")}
	transport.owner.last = evidence
	if request.Body != nil {
		request.Body = cliHashingBody{request.Body, evidence.request}
	}
	response, err := transport.RoundTripper.RoundTrip(request)
	if response != nil && response.Body != nil {
		evidence.response = newCLIPrefixHash(transport.owner.hashKey[:], "relay-cli/observed-response/v1")
		response.Body = cliHashingBody{response.Body, evidence.response}
	}
	return response, err
}

func newProbeCLIRunner(ctx context.Context, rows []tsvRow, deps probeCLIDeps) (*probeCLIRunner, error) {
	directory, err := os.MkdirTemp("", "relay-probe-cli-")
	if err != nil {
		return nil, err
	}
	if err := cliRestrictPrivatePath(directory); err != nil {
		os.Remove(directory)
		return nil, err
	}
	runner := &probeCLIRunner{directory: directory, transports: &cliProbeTransports{manager: outbound.NewManager(), override: deps.transport}, controls: map[string]cliPreparedControl{}, now: deps.now}
	complete := false
	defer func() {
		if !complete {
			runner.Close()
		}
	}()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	runner.transports.hashKey = key
	cipher, err := store.NewCipher(hex.EncodeToString(key[:]))
	if err != nil {
		return nil, err
	}
	runner.store, err = store.Open(filepath.Join(directory, "probe.db"), cipher)
	if err != nil {
		return nil, err
	}
	admin := configadmin.New(runner.store, nil)
	for siteIndex, row := range rows {
		endpoints := make([]configadmin.EndpointMutation, 0, 5)
		for _, endpoint := range []model.EndpointKind{model.EndpointModels, model.EndpointMessages, model.EndpointCountTokens, model.EndpointResponses, model.EndpointChatCompletions} {
			mode := model.AuthModeBearer
			if endpoint == model.EndpointMessages || endpoint == model.EndpointCountTokens {
				mode = model.AuthModeXAPIKey
			}
			endpoints = append(endpoints, configadmin.EndpointMutation{Endpoint: endpoint, AuthProfile: model.EndpointAuthProfile{Mode: mode, SecretRef: "upstream_api_key"}})
		}
		up, err := admin.CreateUpstream(ctx, model.Upstream{Name: row.Alias, BaseURL: row.BaseURL, APIKey: row.APIKey, Enabled: true, ProbeMode: model.ProbeModeLazy}, endpoints)
		if err != nil {
			return nil, err
		}
		runner.candidates = append(runner.candidates, cliProbeCandidate{alias: row.Alias, up: &up, endpoint: model.EndpointModels})
		for _, group := range []struct {
			models   []string
			protocol model.Protocol
		}{{row.ClaudeModels, model.ProtoAnthropic}, {row.GPTModels, model.ProtoOpenAIChat}, {row.GPTModels, model.ProtoOpenAIResponses}} {
			for modelIndex, upstreamModel := range group.models {
				name := row.Alias + "-" + string(group.protocol) + "-" + strconv.Itoa(siteIndex) + "-" + strconv.Itoa(modelIndex)
				mn, err := admin.CreateModelName(ctx, model.ModelName{Name: name, Protocol: group.protocol, Enabled: true})
				if err != nil {
					return nil, err
				}
				route, err := admin.CreateRoute(ctx, model.Route{UpstreamID: up.ID, ModelNameID: mn.ID, UpstreamModel: upstreamModel, Enabled: true, Weight: 100})
				if err != nil {
					return nil, err
				}
				endpoint, _ := group.protocol.Endpoint()
				candidate := cliProbeCandidate{alias: row.Alias, modelAlias: "model-" + strconv.Itoa(modelIndex+1), up: &up, mn: &mn, route: &route, endpoint: endpoint}
				runner.candidates = append(runner.candidates, candidate)
				if group.protocol == model.ProtoAnthropic {
					candidate.endpoint = model.EndpointCountTokens
					runner.candidates = append(runner.candidates, candidate)
				}
			}
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner.source = livecfg.New(runner.store, log)
	if err := runner.source.Refresh(); err != nil {
		return nil, err
	}
	sequence, err := observationseq.Open(ctx, runner.store)
	if err != nil {
		return nil, err
	}
	runner.controller, err = runstate.NewController(runner.store)
	if err != nil {
		return nil, err
	}
	runner.coordinator = probe.NewSyntheticCoordinator(runner.controller.Current().State)
	recipes := probe.NewRecipeResolver(runner.store).WithNotFound(func(err error) bool { return errors.Is(err, store.ErrNotFound) })
	runner.preparer = probe.NewScheduler(runner.source, health.NewTracker(runner.source), health.NewReachabilityTracker(runner.source), log).WithRecipes(recipes).WithSequencer(sequence).WithRunState(runner.controller)
	if err := runner.coordinator.BindResumeTarget(runner.preparer); err != nil {
		return nil, err
	}
	if err := runner.controller.BindSyntheticController(runner.coordinator); err != nil {
		return nil, err
	}
	recorder := probe.NewResultRecorder(runner.store, health.NewObservationReducer(nil), nil, nil)
	runner.executor = probe.NewExecutor(outbound.NewProvider(runner.source, runner.store, outbound.NewResolver(cipher)), runner.store, recipes, runner.transports, recorder, cliSyntheticAdmission{runner.coordinator}, probe.WallClock(), log)
	complete = true
	return runner, nil
}

func (runner *probeCLIRunner) Close() {
	if runner.coordinator != nil {
		runner.coordinator.Close()
	}
	if runner.controller != nil {
		runner.controller.Close()
	}
	if runner.transports != nil {
		runner.transports.manager.CloseIdleConnections()
	}
	if runner.store != nil {
		runner.store.Close()
	}
	if runner.directory != "" {
		os.RemoveAll(runner.directory)
	}
}

func (runner *probeCLIRunner) prepareControls(ctx context.Context, manifest *controlManifest) error {
	for _, candidate := range runner.candidates {
		fixture := findControl(manifest, candidate.alias, candidate.endpoint)
		if fixture == nil {
			continue
		}
		endpoint, err := runner.store.Endpoint(ctx, candidate.up.ID, candidate.endpoint)
		if err != nil {
			return err
		}
		endpoint.AuthProfile = fixture.auth
		if err := runner.store.UpdateEndpoint(endpoint, endpoint.Revision); err != nil {
			return err
		}
		scope, scopeID := model.RecipeScopeUpstream, candidate.up.ID
		body := fixture.body
		if candidate.route != nil {
			scope, scopeID = model.RecipeScopeRoute, candidate.route.ID
			body, err = proxy.ReplaceModel(body, candidate.route.UpstreamModel)
			if err != nil {
				return err
			}
		}
		recipeID, err := runner.store.CreateRecipe(scope, scopeID, candidate.endpoint)
		if err != nil {
			return err
		}
		profile := model.TimeoutL2Standard
		if candidate.endpoint == model.EndpointModels {
			profile = model.TimeoutL1
		} else if candidate.endpoint == model.EndpointCountTokens {
			profile = model.TimeoutCountTokens
		}
		version := &model.ProbeRecipeVersion{RecipeID: recipeID, Origin: model.RecipeManual, Method: candidate.endpoint.Method(), FixedRawQuery: fixture.rawQuery, Headers: fixture.headers, Body: body, BodyIsText: true, StreamExpected: candidate.endpoint != model.EndpointModels && candidate.endpoint != model.EndpointCountTokens, TimeoutProfile: profile}
		if err := runner.store.AddRecipeVersion(version, 1); err != nil {
			return err
		}
		runner.controls[candidateControlKey(candidate)] = cliPreparedControl{fixture: fixture, versionID: version.ID, revision: 2}
	}
	runner.source.Invalidate()
	return runner.source.Refresh()
}

func (runner *probeCLIRunner) execute(ctx context.Context, candidate cliProbeCandidate) (probeResultRow, error) {
	var control *probeControlResult
	if prepared, ok := runner.controls[candidateControlKey(candidate)]; ok {
		if !controlFresh(prepared.fixture.entry, runner.now()) {
			return probeResultRow{}, errCLIPrivateInput
		}
		completed, err := time.Parse(time.RFC3339Nano, prepared.fixture.entry.CompletedAt)
		if err != nil {
			return probeResultRow{}, errCLIPrivateInput
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, completed.Add(controlFreshness))
		defer cancel()
		service := probe.NewService(runner.store, runner.executor, nil, runner.source, nil, nil).WithManualPreparer(runner.preparer)
		var routeID int64
		if candidate.route != nil {
			routeID = candidate.route.ID
		}
		runner.transports.last = nil
		execution, err := service.Test(ctx, prepared.versionID, probe.ManualTestInput{RouteID: routeID, ExpectedRevision: prepared.revision})
		if err != nil {
			return probeResultRow{}, err
		}
		control = &probeControlResult{Success: execution.Success, Status: execution.StatusCode, ErrorClass: string(execution.ErrorClass), SentAtMS: execution.SentAtMS, DoneAtMS: execution.DoneAtMS}
		control.EstimatedInputTokens, control.ObservedOutputTokens, control.ExpectedCancel = execution.EstimatedInputTokens, execution.ObservedOutputTokens, execution.ExpectedCancel
		control.RequestHash, control.ResponseHash = runner.transports.evidence()
		// The budget starts at the original capture completion, not at a later
		// replay. Slow earlier sites never silently make old controls fresh.
		if !controlFresh(prepared.fixture.entry, runner.now()) {
			return probeResultRow{}, errCLIPrivateInput
		}
	}
	request := probe.ExecutionRequest{ExecutionID: sample.NewReqID(), Trigger: model.TriggerManual, Upstream: candidate.up, ModelName: candidate.mn, Route: candidate.route, Endpoint: candidate.endpoint, Mode: probe.ObserveProbe}
	if err := runner.preparer.PrepareManual(ctx, &request); err != nil {
		return probeResultRow{}, err
	}
	runner.transports.last = nil
	result, err := runner.executor.Execute(ctx, request)
	if err != nil {
		return probeResultRow{}, err
	}
	execution := result.Execution
	row := probeResultRow{Alias: candidate.alias, Endpoint: string(candidate.endpoint), ModelAlias: candidate.modelAlias,
		HTTPStatus: execution.StatusCode, DecisionSuccess: result.Decision.Success,
		DecisionReachable: result.Decision.Reachable, Capability: string(result.Decision.Capability), ErrorClass: string(result.Decision.ErrorClass), ControlStatus: "control_missing",
		EstimatedTokens: execution.EstimatedInputTokens + execution.ObservedOutputTokens, Control: control,
		RecipeStorage: string(execution.RecipeStorage), RecipeOrigin: string(execution.RecipeOrigin), RecipeVersionID: execution.RecipeVersionID, AuthRevision: execution.AuthProfileRevision,
		SentAtMS: execution.SentAtMS, ResponseHeaderAtMS: execution.ResponseHeaderAtMS, FirstByteAtMS: execution.FirstByteAtMS, FirstEventAtMS: execution.FirstEventAtMS, FirstSemanticAtMS: execution.FirstSemanticAtMS, DoneAtMS: execution.DoneAtMS}
	row.RequestHash, row.ResponseHash = runner.transports.evidence()
	row.RequestBytes, row.ResponseBytes, row.EstimatedInputTokens, row.ObservedOutputTokens, row.ExpectedCancel = execution.RequestBytes, execution.ResponseBytes, execution.EstimatedInputTokens, execution.ObservedOutputTokens, execution.ExpectedCancel
	if row.RequestHash != "" {
		row.RequestHashScope = "observed_request_body_prefix"
	}
	if row.ResponseHash != "" {
		row.ResponseHashScope = "observed_wire_prefix"
	}
	if execution.GotConnAtMS > 0 && execution.SentAtMS > 0 {
		row.ConnectMS = execution.GotConnAtMS - execution.SentAtMS
	}
	if execution.FirstSemanticAtMS > 0 && execution.SentAtMS > 0 {
		row.TTFTMS = execution.FirstSemanticAtMS - execution.SentAtMS
	}
	if candidate.endpoint == model.EndpointModels {
		row.ControlStatus = "not_applicable"
	}
	if control != nil {
		row.ControlStatus = "paired"
		row.CompatOK = control.Success && row.DecisionSuccess
		if control.Success && !row.DecisionSuccess {
			row.ControlStatus = "control_ok_probe_fail"
		} else if !control.Success {
			row.ControlStatus = "control_failed"
		}
	}
	return row, nil
}
