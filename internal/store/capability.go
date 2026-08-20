package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime/debug"

	"github.com/279814/relay-gate/internal/model"
	"github.com/279814/relay-gate/internal/observation"
	"github.com/279814/relay-gate/internal/revisioncodec"
)

func (store *Store) InsertProbeExecution(ctx context.Context, execution *model.ProbeExecution) error {
	if execution == nil {
		return model.WrapValidation("probe execution 不能为空")
	}
	copyValue := *execution
	if copyValue.ReachabilityDisposition == "" {
		copyValue.ReachabilityDisposition = model.ApplyNotApplicable
	}
	if copyValue.CapabilityDisposition == "" {
		copyValue.CapabilityDisposition = model.ApplyNotApplicable
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	existing, err := loadExecutionEvidence(ctx, tx, copyValue.ID)
	if err == nil {
		if existing != copyValue.EvidenceHash {
			return ErrIdempotencyConflict
		}
		return tx.Commit()
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := insertProbeExecutionTx(ctx, tx, &copyValue); err != nil {
		return err
	}
	if err := recordExecutionCostTx(ctx, tx, copyValue); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CommitProbeObservation(ctx context.Context, value *model.ProbeObservation, reducer observation.StateReducer) (result model.ProbeApplyResult, err error) {
	if value == nil || reducer == nil {
		return result, model.WrapValidation("observation/reducer 不能为空")
	}
	execution := value.Execution
	if err := validateProbeExecutionEnvelope(execution); err != nil {
		return result, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	existingEvidence, existingErr := loadExecutionEvidence(ctx, tx, execution.ID)
	if existingErr == nil {
		if existingEvidence != execution.EvidenceHash {
			return result, ErrIdempotencyConflict
		}
		result, err = loadStoredApplyResult(ctx, tx, execution)
		if err != nil {
			return result, err
		}
		if err = tx.Commit(); err != nil {
			return result, err
		}
		return result, nil
	}
	if !errors.Is(existingErr, ErrNotFound) {
		return result, existingErr
	}

	execution.ReachabilityDisposition, result.CommittedReachability, err = store.reduceReachabilityTx(ctx, tx, execution, value, reducer)
	if err != nil {
		return result, err
	}
	execution.CapabilityDisposition, result.CommittedCapability, err = store.reduceCapabilityTx(ctx, tx, execution, value, reducer)
	if err != nil {
		return result, err
	}
	result.Reachability = execution.ReachabilityDisposition
	result.Capability = execution.CapabilityDisposition
	if err = insertProbeExecutionTx(ctx, tx, &execution); err != nil {
		return result, err
	}
	if err = recordExecutionCostTx(ctx, tx, execution); err != nil {
		return result, err
	}
	result.ExecutionStored = true
	if err = tx.Commit(); err != nil {
		return result, err
	}
	return result, nil
}

func validateProbeExecutionEnvelope(execution model.ProbeExecution) error {
	if execution.ID == "" || execution.EvidenceHash == "" || execution.ObservationOrder <= 0 {
		return model.WrapValidation("execution id/evidence/order 无效")
	}
	if !execution.Endpoint.Valid() || execution.UpstreamID <= 0 || !execution.Trigger.Valid() {
		return model.WrapValidation("execution target/trigger 无效")
	}
	identity := model.RecipeIdentity{
		Storage: execution.RecipeStorage, Origin: execution.RecipeOrigin,
		DBVersionID: execution.RecipeVersionID, ClientProfileID: execution.ClientProfileID,
		TemplateID: execution.TemplateID, Revision: execution.RecipeIdentityRevision,
	}
	if err := identity.Validate(); err != nil {
		return err
	}
	return nil
}

func loadExecutionEvidence(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var hash string
	if err := tx.QueryRowContext(ctx, `SELECT evidence_hash FROM probe_execution WHERE id=?`, id).Scan(&hash); errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	return hash, nil
}

func loadStoredApplyResult(ctx context.Context, tx *sql.Tx, execution model.ProbeExecution) (model.ProbeApplyResult, error) {
	result := model.ProbeApplyResult{ExecutionStored: true}
	if err := tx.QueryRowContext(ctx, `SELECT reachability_disposition,capability_disposition
		FROM probe_execution WHERE id=?`, execution.ID).Scan(&result.Reachability, &result.Capability); err != nil {
		return result, err
	}
	if result.Reachability == model.ApplyCurrent {
		row, err := loadReachability(ctx, tx, execution.UpstreamID)
		if err != nil {
			return result, err
		}
		if row.ObservationToken == execution.ReachabilityToken && row.LastObservationOrder == execution.ObservationOrder {
			result.CommittedReachability = row
		}
	}
	if result.Capability == model.ApplyCurrent {
		row, err := loadCapability(ctx, tx, execution)
		if err != nil {
			return result, err
		}
		if row.ObservationToken == execution.CapabilityToken && row.LastObservationOrder == execution.ObservationOrder {
			result.CommittedCapability = row
		}
	}
	return result, nil
}

func (store *Store) reduceReachabilityTx(ctx context.Context, tx *sql.Tx, execution model.ProbeExecution, value *model.ProbeObservation, reducer observation.StateReducer) (model.ApplyDisposition, *model.UpstreamReachability, error) {
	if value.ReachabilityExpectation == nil || value.ReachabilityPolicy == nil {
		return model.ApplyNotApplicable, nil, nil
	}
	expectation := value.ReachabilityExpectation
	if expectation.UpstreamID != execution.UpstreamID || expectation.PolicySelector != execution.ReachabilityPolicySelector ||
		expectation.Revision.NetworkRevision != execution.UpstreamNetworkRevision ||
		expectation.Revision.SettingsFingerprint != execution.ReachabilitySettingsFingerprint ||
		expectation.ObservationToken != execution.ReachabilityToken ||
		revisioncodec.NewReachabilityToken(expectation.Revision) != expectation.ObservationToken {
		return model.ApplyConfigStale, nil, nil
	}
	currentRevision, err := currentReachabilityRevisionForUpstream(ctx, tx, expectation.UpstreamID, expectation.PolicySelector)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return model.ApplyConfigStale, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if currentRevision != expectation.Revision {
		return model.ApplyConfigStale, nil, nil
	}
	current, err := loadReachability(ctx, tx, execution.UpstreamID)
	if errors.Is(err, ErrNotFound) {
		current = nil
	} else if err != nil {
		return "", nil, err
	}
	if current != nil && current.LastObservationOrder >= execution.ObservationOrder {
		return model.ApplySuperseded, nil, nil
	}
	reduced, err := callReachabilityReducer(reducer, current, execution, *value.ReachabilityPolicy)
	if err != nil {
		return "", nil, err
	}
	if reduced == nil {
		return "", nil, errors.New("reachability reducer 返回 nil")
	}
	reduced.UpstreamID = execution.UpstreamID
	reduced.PolicySelector = expectation.PolicySelector
	reduced.ObservedNetworkRevision = expectation.Revision.NetworkRevision
	reduced.SettingsFingerprint = expectation.Revision.SettingsFingerprint
	reduced.ObservationToken = expectation.ObservationToken
	reduced.LastObservationOrder = execution.ObservationOrder
	if err := saveReachability(ctx, tx, reduced); err != nil {
		return "", nil, err
	}
	copyValue := *reduced
	return model.ApplyCurrent, &copyValue, nil
}

func currentReachabilityRevisionForUpstream(ctx context.Context, tx *sql.Tx, upstreamID int64, selector model.EvidencePolicySelector) (model.ReachabilityRevision, error) {
	var revision model.ReachabilityRevision
	if err := tx.QueryRowContext(ctx, `SELECT network_revision FROM upstream WHERE id=?`, upstreamID).Scan(&revision.NetworkRevision); errors.Is(err, sql.ErrNoRows) {
		return revision, ErrNotFound
	} else if err != nil {
		return revision, err
	}
	settings, err := loadSettingsTx(ctx, tx)
	if err != nil {
		return revision, err
	}
	policy, err := revisioncodec.BuildReachabilityEvidencePolicy(settings, selector)
	if err != nil {
		return revision, err
	}
	revision.SettingsFingerprint = revisioncodec.ReachabilitySettingsFingerprint(policy)
	return revision, nil
}

func callReachabilityReducer(reducer observation.StateReducer, current *model.UpstreamReachability, execution model.ProbeExecution, policy model.ReachabilityReductionPolicy) (result *model.UpstreamReachability, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("reachability reducer panic: %v\n%s", recovered, debug.Stack())
		}
	}()
	return reducer.ReduceReachability(cloneReachability(current), execution, policy)
}

func cloneReachability(value *model.UpstreamReachability) *model.UpstreamReachability {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func loadReachability(ctx context.Context, tx *sql.Tx, upstreamID int64) (*model.UpstreamReachability, error) {
	var value model.UpstreamReachability
	if err := tx.QueryRowContext(ctx, `SELECT upstream_id,evidence_kind,endpoint,timeout_profile,state,
		consecutive_ok,consecutive_fail,last_ok_at,last_error_at,last_error,last_connect_ms,last_tls_ms,
		last_header_ms,observed_network_revision,settings_fingerprint,observation_token,last_observation_order
		FROM upstream_reachability WHERE upstream_id=?`, upstreamID).Scan(
		&value.UpstreamID, &value.PolicySelector.Kind, &value.PolicySelector.Endpoint,
		&value.PolicySelector.TimeoutProfile, &value.State, &value.ConsecutiveOK, &value.ConsecutiveFail,
		&value.LastOKAt, &value.LastErrorAt, &value.LastError, &value.LastConnectMS, &value.LastTLSMS,
		&value.LastHeaderMS, &value.ObservedNetworkRevision, &value.SettingsFingerprint,
		&value.ObservationToken, &value.LastObservationOrder); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &value, nil
}

func saveReachability(ctx context.Context, tx *sql.Tx, value *model.UpstreamReachability) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO upstream_reachability
		(upstream_id,evidence_kind,endpoint,timeout_profile,state,consecutive_ok,consecutive_fail,
		 last_ok_at,last_error_at,last_error,last_connect_ms,last_tls_ms,last_header_ms,
		 observed_network_revision,settings_fingerprint,observation_token,last_observation_order)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(upstream_id) DO UPDATE SET
		evidence_kind=excluded.evidence_kind,endpoint=excluded.endpoint,timeout_profile=excluded.timeout_profile,
		state=excluded.state,consecutive_ok=excluded.consecutive_ok,consecutive_fail=excluded.consecutive_fail,
		last_ok_at=excluded.last_ok_at,last_error_at=excluded.last_error_at,last_error=excluded.last_error,
		last_connect_ms=excluded.last_connect_ms,last_tls_ms=excluded.last_tls_ms,last_header_ms=excluded.last_header_ms,
		observed_network_revision=excluded.observed_network_revision,settings_fingerprint=excluded.settings_fingerprint,
		observation_token=excluded.observation_token,last_observation_order=excluded.last_observation_order`,
		value.UpstreamID, value.PolicySelector.Kind, value.PolicySelector.Endpoint, value.PolicySelector.TimeoutProfile,
		value.State, value.ConsecutiveOK, value.ConsecutiveFail, value.LastOKAt, value.LastErrorAt,
		value.LastError, value.LastConnectMS, value.LastTLSMS, value.LastHeaderMS,
		value.ObservedNetworkRevision, value.SettingsFingerprint, value.ObservationToken,
		value.LastObservationOrder)
	return err
}

func (store *Store) reduceCapabilityTx(ctx context.Context, tx *sql.Tx, execution model.ProbeExecution, value *model.ProbeObservation, reducer observation.StateReducer) (model.ApplyDisposition, *model.EndpointCapability, error) {
	if value.CapabilityExpectation == nil || value.CapabilityPolicy == nil ||
		execution.RecipeBindingUse == model.BindingExplicitTest || execution.RecipeBindingUse == model.BindingExplicitProfileTest {
		return model.ApplyNotApplicable, nil, nil
	}
	expectation := value.CapabilityExpectation
	if expectation.Target.UpstreamID != execution.UpstreamID || expectation.Target.RouteID != execution.RouteID ||
		expectation.Target.Endpoint != execution.Endpoint || expectation.PolicySelector != execution.CapabilityPolicySelector ||
		expectation.BindingFacts.Use != execution.RecipeBindingUse ||
		expectation.ObservationToken != execution.CapabilityToken ||
		revisioncodec.NewObservationToken(expectation.Revision) != expectation.ObservationToken {
		return model.ApplyConfigStale, nil, nil
	}
	bindingCurrent, err := recipeBindingFactsCurrent(ctx, tx, expectation)
	if err != nil {
		return "", nil, err
	}
	if !bindingCurrent {
		return model.ApplyConfigStale, nil, nil
	}
	current, err := currentSemanticRevision(ctx, tx, expectation)
	if errors.Is(err, ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return model.ApplyConfigStale, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if !reflect.DeepEqual(current, expectation.Revision) {
		return model.ApplyConfigStale, nil, nil
	}
	currentRow, err := loadCapability(ctx, tx, execution)
	if errors.Is(err, ErrNotFound) {
		currentRow = nil
	} else if err != nil {
		return "", nil, err
	}
	if currentRow != nil && currentRow.LastObservationOrder >= execution.ObservationOrder {
		return model.ApplySuperseded, nil, nil
	}
	reduced, err := callCapabilityReducer(reducer, currentRow, execution, *value.CapabilityPolicy)
	if err != nil {
		return "", nil, err
	}
	if reduced == nil {
		return "", nil, errors.New("capability reducer 返回 nil")
	}
	reduced.ScopeType = expectation.Target.Scope
	if reduced.ScopeType == model.RecipeScopeRoute {
		reduced.ScopeID = expectation.Target.RouteID
	} else {
		reduced.ScopeID = expectation.Target.UpstreamID
	}
	reduced.Endpoint = execution.Endpoint
	reduced.EndpointID = expectation.Revision.EndpointID
	reduced.PolicySelector = expectation.PolicySelector
	reduced.ObservationToken = expectation.ObservationToken
	reduced.UpstreamNetworkRevision = expectation.Revision.UpstreamNetwork
	reduced.UpstreamCredentialRevision = expectation.Revision.UpstreamCredential
	reduced.EndpointRevision = expectation.Revision.EndpointRevision
	reduced.ModelCapabilityRevision = expectation.Revision.ModelCapability
	reduced.RouteCapabilityRevision = expectation.Revision.RouteCapability
	reduced.AuthProfileRevision = expectation.Revision.AuthProfile
	reduced.RecipeBindingRevision = expectation.Revision.RecipeBindingRevision
	reduced.ProbeSettingsFingerprint = expectation.Revision.ProbeSettingsFingerprint
	reduced.ProbeSecretRevisionsHash = revisioncodec.SecretRevisionSetHash(expectation.Revision.ProbeSecrets)
	reduced.RequestTransformBindingRevision = expectation.Revision.RequestTransform
	reduced.LastObservationOrder = execution.ObservationOrder
	if err := saveCapability(ctx, tx, reduced); err != nil {
		return "", nil, err
	}
	copyValue := *reduced
	return model.ApplyCurrent, &copyValue, nil
}

type publishedBindingRow struct {
	recipeID        int64
	versionID       int64
	bindingRevision int64
	origin          model.RecipeSource
}

func recipeBindingFactsCurrent(ctx context.Context, tx *sql.Tx, expectation *model.SemanticExpectation) (bool, error) {
	facts := expectation.BindingFacts
	routeBinding, err := loadPublishedBinding(ctx, tx, model.RecipeScopeRoute,
		expectation.Target.RouteID, expectation.Target.Endpoint)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return false, err
	}
	upstreamBinding, upstreamErr := loadPublishedBinding(ctx, tx, model.RecipeScopeUpstream,
		expectation.Target.UpstreamID, expectation.Target.Endpoint)
	if upstreamErr != nil && !errors.Is(upstreamErr, ErrNotFound) {
		return false, upstreamErr
	}
	var profileID, profileRevision int64
	profileErr := tx.QueryRowContext(ctx, `SELECT id,revision FROM client_probe_profile
		WHERE upstream_id=? AND endpoint=? AND status='tested'`, expectation.Target.UpstreamID,
		expectation.Target.Endpoint).Scan(&profileID, &profileRevision)
	if profileErr != nil && !errors.Is(profileErr, sql.ErrNoRows) {
		return false, profileErr
	}
	identity := expectation.Revision.RecipeIdentity
	switch facts.ResolvedLayer {
	case model.ResolvedRoute:
		return routeBinding != nil && routeBinding.recipeID == facts.RouteRecipeID &&
			routeBinding.versionID == facts.RoutePublishedVersionID &&
			routeBinding.bindingRevision == facts.RouteBindingRevision &&
			identity.Storage == model.RecipeStorageDB && identity.DBVersionID == routeBinding.versionID &&
			identity.Origin == routeBinding.origin && expectation.Revision.RecipeBindingRevision == routeBinding.bindingRevision, nil
	case model.ResolvedUpstream:
		return routeBinding == nil && upstreamBinding != nil &&
			upstreamBinding.recipeID == facts.UpstreamRecipeID &&
			upstreamBinding.versionID == facts.UpstreamPublishedVersionID &&
			upstreamBinding.bindingRevision == facts.UpstreamBindingRevision &&
			identity.Storage == model.RecipeStorageDB && identity.DBVersionID == upstreamBinding.versionID &&
			identity.Origin == upstreamBinding.origin && expectation.Revision.RecipeBindingRevision == upstreamBinding.bindingRevision, nil
	case model.ResolvedProfile:
		return routeBinding == nil && upstreamBinding == nil && profileErr == nil &&
			profileID == facts.TestedProfileID && profileRevision == facts.TestedProfileRevision &&
			identity.Storage == model.RecipeStorageProfile && identity.ClientProfileID == profileID &&
			identity.Revision == profileRevision && expectation.Revision.RecipeBindingRevision == profileRevision, nil
	case model.ResolvedEmbedded:
		return routeBinding == nil && upstreamBinding == nil && errors.Is(profileErr, sql.ErrNoRows) &&
			identity.Storage == model.RecipeStorageEmbedded && identity.TemplateID != "" &&
			expectation.Revision.RecipeBindingRevision == identity.Revision, nil
	default:
		return false, nil
	}
}

func loadPublishedBinding(ctx context.Context, tx *sql.Tx, scope model.RecipeScope, scopeID int64, endpoint model.EndpointKind) (*publishedBindingRow, error) {
	if scopeID <= 0 {
		return nil, ErrNotFound
	}
	column := "upstream_id"
	if scope == model.RecipeScopeRoute {
		column = "route_id"
	}
	var row publishedBindingRow
	query := `SELECT r.id,r.published_version_id,r.active_binding_revision,v.origin
		FROM probe_recipe r JOIN probe_recipe_version v ON v.id=r.published_version_id
		WHERE r.` + column + `=? AND r.endpoint=? AND r.status IN ('published','legacy_compat')`
	if err := tx.QueryRowContext(ctx, query, scopeID, endpoint).Scan(&row.recipeID, &row.versionID,
		&row.bindingRevision, &row.origin); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	return &row, nil
}

func currentSemanticRevision(ctx context.Context, tx *sql.Tx, expectation *model.SemanticExpectation) (model.SemanticRevision, error) {
	current := expectation.Revision
	var upstreamNetwork, upstreamCredential, endpointID, endpointRevision, authRevision int64
	if err := tx.QueryRowContext(ctx, `SELECT u.network_revision,u.credential_revision,e.id,e.revision,e.auth_profile_revision
		FROM upstream u JOIN upstream_endpoint e ON e.upstream_id=u.id AND e.endpoint=? WHERE u.id=?`,
		expectation.Target.Endpoint, expectation.Target.UpstreamID).Scan(&upstreamNetwork, &upstreamCredential,
		&endpointID, &endpointRevision, &authRevision); errors.Is(err, sql.ErrNoRows) {
		return model.SemanticRevision{}, ErrNotFound
	} else if err != nil {
		return model.SemanticRevision{}, err
	}
	current.UpstreamNetwork = upstreamNetwork
	current.UpstreamCredential = upstreamCredential
	current.EndpointID = endpointID
	current.EndpointRevision = endpointRevision
	current.AuthProfile = authRevision
	if expectation.Target.Scope == model.RecipeScopeRoute {
		if err := tx.QueryRowContext(ctx, `SELECT r.capability_revision,m.capability_revision
			FROM route r JOIN model_name m ON m.id=r.model_name_id WHERE r.id=? AND r.upstream_id=?`,
			expectation.Target.RouteID, expectation.Target.UpstreamID).Scan(&current.RouteCapability, &current.ModelCapability); err != nil {
			return model.SemanticRevision{}, err
		}
	} else {
		current.RouteCapability, current.ModelCapability = 0, 0
	}
	settings, err := loadSettingsTx(ctx, tx)
	if err != nil {
		return model.SemanticRevision{}, err
	}
	policy, err := revisioncodec.BuildCapabilityEvidencePolicy(settings, expectation.PolicySelector)
	if err != nil {
		return model.SemanticRevision{}, err
	}
	current.ProbeSettingsFingerprint = revisioncodec.ProbeSettingsFingerprint(policy)
	for index, secret := range current.ProbeSecrets {
		var id, revision int64
		err := tx.QueryRowContext(ctx, `SELECT id,revision FROM probe_secret WHERE name=?`, secret.Name).Scan(&id, &revision)
		if errors.Is(err, sql.ErrNoRows) {
			current.ProbeSecrets[index] = model.SecretRevision{Name: secret.Name}
			continue
		}
		if err != nil {
			return model.SemanticRevision{}, err
		}
		current.ProbeSecrets[index] = model.SecretRevision{ID: id, Name: secret.Name, Revision: revision, Resolved: true}
	}
	return current, nil
}

func callCapabilityReducer(reducer observation.StateReducer, current *model.EndpointCapability, execution model.ProbeExecution, policy model.CapabilityReductionPolicy) (result *model.EndpointCapability, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("capability reducer panic: %v\n%s", recovered, debug.Stack())
		}
	}()
	return reducer.ReduceCapability(cloneCapability(current), execution, policy)
}

func cloneCapability(value *model.EndpointCapability) *model.EndpointCapability {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func loadCapability(ctx context.Context, tx *sql.Tx, execution model.ProbeExecution) (*model.EndpointCapability, error) {
	condition := "scope_upstream_id=? AND scope_route_id IS NULL"
	scopeID := execution.UpstreamID
	if execution.RouteID > 0 {
		condition = "scope_route_id=? AND scope_upstream_id IS NULL"
		scopeID = execution.RouteID
	}
	var value model.EndpointCapability
	if err := tx.QueryRowContext(ctx, `SELECT endpoint,endpoint_id,evidence_kind,timeout_profile,state,
		observation_token,resolved_url_hash,upstream_network_revision,upstream_credential_revision,
		endpoint_revision,model_capability_revision,route_capability_revision,auth_profile_revision,
		recipe_binding_revision,probe_settings_fingerprint,probe_secret_revisions_hash,
		request_transform_binding_revision,observed_at,expires_at,status_code,error_class,redacted_detail,
		last_observation_order,last_real_ok_at,last_real_ok_token FROM endpoint_capability WHERE `+
		condition+` AND endpoint=?`, scopeID, execution.Endpoint).Scan(
		&value.Endpoint, &value.EndpointID, &value.PolicySelector.Kind, &value.PolicySelector.TimeoutProfile,
		&value.State, &value.ObservationToken, &value.ResolvedURLHash, &value.UpstreamNetworkRevision,
		&value.UpstreamCredentialRevision, &value.EndpointRevision, &value.ModelCapabilityRevision,
		&value.RouteCapabilityRevision, &value.AuthProfileRevision, &value.RecipeBindingRevision,
		&value.ProbeSettingsFingerprint, &value.ProbeSecretRevisionsHash,
		&value.RequestTransformBindingRevision, &value.ObservedAt, &value.ExpiresAt, &value.StatusCode,
		&value.ErrorClass, &value.RedactedDetail, &value.LastObservationOrder, &value.LastRealOKAt,
		&value.LastRealOKToken); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	value.PolicySelector.Endpoint = value.Endpoint
	if execution.RouteID > 0 {
		value.ScopeType, value.ScopeID = model.RecipeScopeRoute, execution.RouteID
	} else {
		value.ScopeType, value.ScopeID = model.RecipeScopeUpstream, execution.UpstreamID
	}
	return &value, nil
}

func saveCapability(ctx context.Context, tx *sql.Tx, value *model.EndpointCapability) error {
	var upstreamID, routeID any
	if value.ScopeType == model.RecipeScopeRoute {
		routeID = value.ScopeID
	} else {
		upstreamID = value.ScopeID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO endpoint_capability
		(scope_upstream_id,scope_route_id,endpoint,endpoint_id,evidence_kind,timeout_profile,state,
		 observation_token,resolved_url_hash,upstream_network_revision,upstream_credential_revision,
		 endpoint_revision,model_capability_revision,route_capability_revision,auth_profile_revision,
		 recipe_binding_revision,probe_settings_fingerprint,probe_secret_revisions_hash,
		 request_transform_binding_revision,observed_at,expires_at,status_code,error_class,redacted_detail,
		 last_observation_order,last_real_ok_at,last_real_ok_token)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT DO UPDATE SET endpoint_id=excluded.endpoint_id,evidence_kind=excluded.evidence_kind,
		timeout_profile=excluded.timeout_profile,state=excluded.state,observation_token=excluded.observation_token,
		resolved_url_hash=excluded.resolved_url_hash,upstream_network_revision=excluded.upstream_network_revision,
		upstream_credential_revision=excluded.upstream_credential_revision,endpoint_revision=excluded.endpoint_revision,
		model_capability_revision=excluded.model_capability_revision,route_capability_revision=excluded.route_capability_revision,
		auth_profile_revision=excluded.auth_profile_revision,recipe_binding_revision=excluded.recipe_binding_revision,
		probe_settings_fingerprint=excluded.probe_settings_fingerprint,
		probe_secret_revisions_hash=excluded.probe_secret_revisions_hash,
		request_transform_binding_revision=excluded.request_transform_binding_revision,
		observed_at=excluded.observed_at,expires_at=excluded.expires_at,status_code=excluded.status_code,
		error_class=excluded.error_class,redacted_detail=excluded.redacted_detail,
		last_observation_order=excluded.last_observation_order,last_real_ok_at=excluded.last_real_ok_at,
		last_real_ok_token=excluded.last_real_ok_token`,
		upstreamID, routeID, value.Endpoint, value.EndpointID, value.PolicySelector.Kind,
		value.PolicySelector.TimeoutProfile, value.State, value.ObservationToken, value.ResolvedURLHash,
		value.UpstreamNetworkRevision, value.UpstreamCredentialRevision, value.EndpointRevision,
		value.ModelCapabilityRevision, value.RouteCapabilityRevision, value.AuthProfileRevision,
		value.RecipeBindingRevision, value.ProbeSettingsFingerprint, value.ProbeSecretRevisionsHash,
		value.RequestTransformBindingRevision, value.ObservedAt, value.ExpiresAt, value.StatusCode,
		value.ErrorClass, value.RedactedDetail, value.LastObservationOrder, value.LastRealOKAt,
		value.LastRealOKToken)
	return err
}

func loadSettingsTx(ctx context.Context, tx *sql.Tx) (model.Settings, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT value FROM setting WHERE key=?`, keySettings).Scan(&raw); errors.Is(err, sql.ErrNoRows) {
		return model.DefaultSettings(), nil
	} else if err != nil {
		return model.Settings{}, err
	}
	return DecodeLegacySettings(raw)
}

func insertProbeExecutionTx(ctx context.Context, tx *sql.Tx, execution *model.ProbeExecution) error {
	factsJSON, err := json.Marshal(execution.RecipeBindingFacts)
	if err != nil {
		return err
	}
	createdAt := execution.DoneAtMS
	if createdAt == 0 {
		createdAt = nowMS()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO probe_execution (
		id,trigger,upstream_id,upstream_network_revision,upstream_credential_revision,
		reachability_evidence_kind,reachability_timeout_profile,capability_evidence_kind,
		capability_timeout_profile,reachability_settings_fingerprint,probe_settings_fingerprint,
		endpoint_id,endpoint_revision,model_capability_revision,route_capability_revision,
		auth_profile_revision,probe_secret_revisions_hash,request_transform_binding_revision,
		route_id,endpoint,recipe_binding_use,recipe_id,recipe_version_id,recipe_storage,recipe_origin,
		client_profile_id,template_id,recipe_binding_revision,recipe_identity_revision,
		recipe_binding_facts_json,real_request_shape_hash,real_request_shape_learnable,
		real_request_shape_unavailable_reason,reachability_token,capability_token,resolved_url_hash,
		request_url_hash,evidence_hash,status_code,error_class,capability_state,observation_scope,
		reachable,final,success,semantic_seen,normal_end_seen,partial,candidate_disposition,
		redacted_detail,sent_at_ms,tls_handshake_start_at_ms,tls_handshake_done_at_ms,got_conn_at_ms,
		response_header_at_ms,first_byte_at_ms,first_event_at_ms,first_semantic_at_ms,done_at_ms,
		request_bytes,response_bytes,estimated_input_tokens,observed_input_tokens,observed_output_tokens,
		retry_after_until_ms,observation_order,expected_cancel,observer_incomplete,
		observer_incomplete_reason,reachability_disposition,capability_disposition,
		calibration_run_id,candidate_ordinal,created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
		?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		execution.ID, execution.Trigger, execution.UpstreamID, execution.UpstreamNetworkRevision,
		execution.UpstreamCredentialRevision, execution.ReachabilityPolicySelector.Kind,
		execution.ReachabilityPolicySelector.TimeoutProfile, execution.CapabilityPolicySelector.Kind,
		execution.CapabilityPolicySelector.TimeoutProfile, execution.ReachabilitySettingsFingerprint,
		execution.ProbeSettingsFingerprint, nullablePositiveID(execution.EndpointID), execution.EndpointRevision,
		execution.ModelCapabilityRevision, execution.RouteCapabilityRevision, execution.AuthProfileRevision,
		execution.ProbeSecretRevisionsHash, execution.RequestTransformBindingRevision,
		nullablePositiveID(execution.RouteID), execution.Endpoint, execution.RecipeBindingUse,
		nullablePositiveID(execution.RecipeID), nullablePositiveID(execution.RecipeVersionID),
		execution.RecipeStorage, execution.RecipeOrigin, nullablePositiveID(execution.ClientProfileID),
		execution.TemplateID, execution.RecipeBindingRevision, execution.RecipeIdentityRevision,
		string(factsJSON), execution.RealRequestShapeHash, execution.RealRequestShapeLearnable,
		execution.RealRequestShapeUnavailableReason, execution.ReachabilityToken, execution.CapabilityToken,
		execution.ResolvedURLHash, execution.RequestURLHash, execution.EvidenceHash, execution.StatusCode,
		execution.ErrorClass, execution.Capability, execution.Scope, execution.Reachable, execution.Final,
		execution.Success, execution.SemanticSeen, execution.NormalEndSeen, execution.Partial,
		execution.CandidateDisposition, execution.RedactedDetail, execution.SentAtMS,
		execution.TLSHandshakeStartAtMS, execution.TLSHandshakeDoneAtMS, execution.GotConnAtMS,
		execution.ResponseHeaderAtMS, execution.FirstByteAtMS, execution.FirstEventAtMS,
		execution.FirstSemanticAtMS, execution.DoneAtMS, execution.RequestBytes, execution.ResponseBytes,
		execution.EstimatedInputTokens, execution.ObservedInputTokens, execution.ObservedOutputTokens,
		execution.RetryAfterUntilMS, execution.ObservationOrder, execution.ExpectedCancel,
		execution.ObserverIncomplete, execution.ObserverIncompleteReason,
		execution.ReachabilityDisposition, execution.CapabilityDisposition,
		nullableString(execution.CalibrationRunID), execution.CandidateOrdinal, createdAt)
	if err != nil {
		if stringsContainsConstraint(err, "probe_execution.id") {
			return ErrIdempotencyConflict
		}
		return err
	}
	return nil
}

func recordExecutionCostTx(ctx context.Context, tx *sql.Tx, execution model.ProbeExecution) error {
	if execution.Trigger == model.TriggerRealTraffic {
		return nil
	}
	evidence, err := revisioncodec.CostEvidenceFromExecution(execution)
	if err != nil {
		return err
	}
	return recordProbeCostEvidenceTx(ctx, tx, "execution:"+execution.ID, evidence)
}

func recordProbeCostEvidenceTx(ctx context.Context, tx *sql.Tx, eventID string, evidence model.ProbeCostEvidenceV1) error {
	hash, err := revisioncodec.NewProbeCostEvidenceHash(evidence)
	if err != nil {
		return err
	}
	var closedThrough string
	if err := tx.QueryRowContext(ctx, `SELECT closed_through_day_utc FROM probe_cost_retention_watermark WHERE singleton=1`).Scan(&closedThrough); err != nil {
		return err
	}
	if closedThrough != "" && evidence.DayUTC <= closedThrough {
		return nil
	}
	result, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO probe_cost_event
		(event_id,day_utc,event_kind,evidence_version,cost_evidence_hash) VALUES (?,?,?,1,?)`,
		eventID, evidence.DayUTC, evidence.Kind, hash)
	if err != nil {
		return err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		var storedDay, storedKind, storedHash string
		var storedVersion int
		if err := tx.QueryRowContext(ctx, `SELECT day_utc,event_kind,evidence_version,cost_evidence_hash
			FROM probe_cost_event WHERE event_id=?`, eventID).Scan(&storedDay, &storedKind, &storedVersion, &storedHash); err != nil {
			return err
		}
		if storedDay != evidence.DayUTC || storedKind != string(evidence.Kind) || storedVersion != 1 || storedHash != hash {
			return ErrIdempotencyConflict
		}
		return nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO probe_cost_daily
		(day_utc,trigger,origin,endpoint,route_id,upstream_id,requests,succeeded,failed,canceled,
		 estimated_input_tokens,observed_output_tokens,canceled_after_semantic,piggyback_l2_saved)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(day_utc,trigger,origin,endpoint,route_id,upstream_id)
		DO UPDATE SET requests=requests+excluded.requests,succeeded=succeeded+excluded.succeeded,
		failed=failed+excluded.failed,canceled=canceled+excluded.canceled,
		estimated_input_tokens=estimated_input_tokens+excluded.estimated_input_tokens,
		observed_output_tokens=observed_output_tokens+excluded.observed_output_tokens,
		canceled_after_semantic=canceled_after_semantic+excluded.canceled_after_semantic,
		piggyback_l2_saved=piggyback_l2_saved+excluded.piggyback_l2_saved`,
		evidence.DayUTC, evidence.Trigger, evidence.Origin, evidence.Endpoint, evidence.RouteID,
		evidence.UpstreamID, evidence.Requests, evidence.Succeeded, evidence.Failed, evidence.Canceled,
		evidence.EstimatedInputTokens, evidence.ObservedOutputTokens, evidence.CanceledAfterSemantic,
		evidence.PiggybackL2Saved)
	return err
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func stringsContainsConstraint(err error, field string) bool {
	return err != nil && (errors.Is(err, sql.ErrNoRows) ||
		containsFold(err.Error(), "unique constraint failed: "+field))
}

func containsFold(value, target string) bool {
	if len(value) < len(target) {
		return false
	}
	for index := 0; index+len(target) <= len(value); index++ {
		if equalFoldASCII(value[index:index+len(target)], target) {
			return true
		}
	}
	return false
}

func equalFoldASCII(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		l, r := left[index], right[index]
		if l >= 'A' && l <= 'Z' {
			l += 'a' - 'A'
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if l != r {
			return false
		}
	}
	return true
}
