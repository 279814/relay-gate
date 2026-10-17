import { field } from './api.mjs';
import { focusFirst } from './modal.mjs';

const read = (row, name) => field(row, name, name.split('_').map(part => ['id', 'url', 'ms', 'api'].includes(part) ? part.toUpperCase() : part[0].toUpperCase() + part.slice(1)).join(''));
const recipePath = (editor) => `/probe-recipes/${read(editor.recipe, 'id')}`;
const versionPath = (editor) => `/probe-recipe-versions/${editor.selected.id}`;
const emptyPage = () => ({ items: [], next_cursor: '', loading: false });
const emptyProfileFilters = () => ({ upstream_id: '', endpoint: '', status: '', client_family: '' });

function initialDraft(endpoint) {
  const models = endpoint === 'models';
  let body = '';
  if (!models) {
    const content = { model: '{{UPSTREAM_MODEL}}' };
    if (endpoint === 'responses') Object.assign(content, { input: '{{PROBE_PROMPT}}', max_output_tokens: 1 });
    else Object.assign(content, { messages: [{ role: 'user', content: '{{PROBE_PROMPT}}' }], ...(endpoint === 'count_tokens' ? {} : { max_tokens: 1 }) });
    body = JSON.stringify(content, null, 2);
  }
  return { method: models ? 'GET' : 'POST', fixed_raw_query: '', headers: '[]', body, encoding: 'text', stream_expected: false, timeout_profile: models ? 'l1' : endpoint === 'count_tokens' ? 'count_tokens' : 'l2_standard' };
}

function editorFor(recipe) {
  return { recipe, versions: emptyPage(), selected: null, draft: initialDraft(read(recipe, 'endpoint')), routeId: read(recipe, 'scope_type') === 'route' ? read(recipe, 'scope_id') : '', preview: null, execution: null, forceAcknowledged: false, busy: false, conflict: false, dirty: false };
}

export function createRecipeAdminFeature(shell, api) {
  if (shell.recipes?.filter) Object.assign(shell.recipes.filter, { upstream_id: '', route_id: '', endpoint: '', status: '' });
  Object.assign(shell, {
    recipeEditor: null,
    recipeCandidateSeed: null,
    profiles: emptyPage(),
    profileFilters: emptyProfileFilters(),
    profileView: null,

    recipeValue: read,
    canRunCandidate() { return this.displayState !== 'paused' && this.displayState !== 'maintenance'; },
    async recipeAdminAction(editor, action) {
      const owner = this.profiles;
      if (!editor || editor.busy || editor.conflict) return false;
      editor.busy = true; this.err = '';
      try { await action(); return true; }
      catch (error) {
        if (this.profiles !== owner) return false;
        if (error.status === 409) { editor.conflict = true; this.err = '配置版本已改变。编辑内容已保留；重新载入并核对后再提交。'; }
        else if (error.data?.persisted) { editor.conflict = true; this.err = `配置已保存（revision ${error.data.new_revision}），运行快照尚未激活。请刷新查看，不要重复提交。`; }
        else this.err = error.message || '操作失败';
        return false;
      } finally { editor.busy = false; }
    },

    async openRecipe(id) {
      const owner = this.profiles;
      try {
        const recipe = await api.get(`/probe-recipes/${encodeURIComponent(id)}`);
        if (this.profiles !== owner) return;
        this.recipeEditor = editorFor(recipe);
        this.recipeDetail = null;
        this._lockModal?.(() => this.closeRecipeEditor());
        await this.loadRecipeVersions(true);
        if (this.profiles !== owner) return;
        this.$nextTick?.(() => focusFirst(this.$refs?.recipeEditorDialog));
      } catch (error) { if (this.profiles === owner) this.err = error.message; }
    },
    closeRecipeEditor() { if (this.recipeEditor?.busy) return; this.recipeEditor = null; this._unlockModal?.(); },
    async reloadRecipeEditor() {
      if (!this.recipeEditor || this.recipeEditor.busy) return;
      if (!confirm('重新载入会丢弃当前未保存的编辑。继续？')) return;
      await this.openRecipe(read(this.recipeEditor.recipe, 'id'));
    },
    async createRecipe() {
      const owner = this.profiles;
      const form = this.recipeForm;
      if (!form || this.busy) return;
      this.busy = true;
      try {
        const recipe = await api.post('/probe-recipes', { scope: form.scope, scope_id: Number(form.scope_id), endpoint: form.endpoint });
        if (this.profiles !== owner) return;
        this.recipeForm = null; await this.loadRecipes(true);
        if (this.profiles !== owner) return;
        await this.openRecipe(read(recipe, 'id'));
        if (this.profiles !== owner) return;
        if (this.recipeCandidateSeed && this.recipeEditor) {
          const seed = this.recipeCandidateSeed; this.recipeCandidateSeed = null;
          this.recipeEditor.draft = { method: seed.method, fixed_raw_query: seed.fixed_raw_query || '', headers: JSON.stringify(seed.headers || [], null, 2), body: seed.body_text ?? seed.body_base64 ?? '', encoding: seed.body_base64 !== undefined ? 'base64' : 'text', stream_expected: !!seed.stream_expected, timeout_profile: seed.timeout_profile };
          this.recipeEditor.dirty = true;
          await this.saveRecipeVersion();
        }
      } catch (error) { if (this.profiles === owner) this.err = error.data?.persisted ? '配方已保存，快照激活待完成，请刷新列表。' : error.message; }
      finally { if (this.profiles === owner) this.busy = false; }
    },
    openSampleRecipeCandidate(candidate) {
      if (!candidate?.endpoint || !candidate?.method) { this.err = '样本候选不完整，请重新导出。'; return; }
      const { method, fixed_raw_query, headers, body_text, body_base64, stream_expected, timeout_profile } = candidate;
      this.recipeCandidateSeed = { method, fixed_raw_query, headers, body_text, body_base64, stream_expected, timeout_profile };
      this.recipeForm = { scope: 'upstream', scope_id: candidate.upstream_id || '', endpoint: candidate.endpoint };
      this.msg = '已导入安全模板。确认作用域后创建手工草稿；不会自动测试或发布。';
    },
    async loadRecipeVersions(reset = true) {
      const editor = this.recipeEditor; if (!editor || editor.versions.loading) return;
      editor.versions.loading = true;
      try {
        const cursor = reset ? '' : editor.versions.next_cursor;
        const page = await api.get(`${recipePath(editor)}/versions?limit=25${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`);
        if (this.recipeEditor !== editor) return;
        editor.versions.items = reset ? page.items : [...editor.versions.items, ...page.items];
        editor.versions.next_cursor = page.next_cursor || '';
        if (reset && page.items.length) {
          const draftID = read(editor.recipe, 'draft_version_id');
          this.selectRecipeVersion(page.items.find(v => v.id === draftID) || page.items[0]);
        }
      } catch (error) { if (this.recipeEditor === editor) this.err = error.message; }
      finally { editor.versions.loading = false; }
    },
    selectRecipeVersion(version) {
      const editor = this.recipeEditor; if (!editor || editor.busy) return;
      editor.selected = version;
      editor.draft = { method: version.method, fixed_raw_query: version.fixed_raw_query || '', headers: JSON.stringify(version.headers || [], null, 2), body: version.body_text ?? version.body_base64 ?? '', encoding: version.body_text !== undefined ? 'text' : 'base64', stream_expected: version.stream_expected, timeout_profile: version.timeout_profile };
      editor.dirty = false;
      this.clearRecipeEvidence();
    },
    clearRecipeEvidence() { if (this.recipeEditor) Object.assign(this.recipeEditor, { preview: null, execution: null, forceAcknowledged: false }); },
    markRecipeDraftChanged() { if (this.recipeEditor) { this.recipeEditor.dirty = true; this.clearRecipeEvidence(); } },
    async saveRecipeVersion() {
      const owner = this.profiles;
      const editor = this.recipeEditor;
      if (!editor || editor.conflict || editor.busy) return;
      await this.recipeAdminAction(editor, async () => {
        const headers = JSON.parse(editor.draft.headers || '[]');
        if (!Array.isArray(headers)) throw new Error('Headers 必须是有序数组，每项包含 name 与 values 数组。');
        const { encoding, body, ...draft } = editor.draft;
        const version = await api.post(`${recipePath(editor)}/versions`, { ...draft, headers, [encoding === 'base64' ? 'body_base64' : 'body_text']: body, expected_revision: read(editor.recipe, 'revision') });
        if (this.profiles !== owner) return;
        editor.recipe = await api.get(recipePath(editor));
        if (this.profiles !== owner) return;
        editor.versions.items.unshift(version); editor.selected = version; editor.dirty = false;
        this.clearRecipeEvidence(); this.msg = `已保存不可变版本 v${version.version}，尚未测试或发布`;
        await this.loadRecipes(true);
      });
    },
    async previewRecipe() {
      const editor = this.recipeEditor; if (!editor?.selected || editor.dirty) return;
      await this.recipeAdminAction(editor, async () => { editor.preview = await api.post(`${versionPath(editor)}/preview`, { route_id: Number(editor.routeId) || 0 }); editor.execution = null; editor.forceAcknowledged = false; });
    },
    async testRecipe() {
      const editor = this.recipeEditor;
      if (!editor?.preview || editor.dirty || !this.canRunCandidate()) return;
      if (!confirm('将向该上游发送一次真实测试请求，可能消耗 token；不会发布此版本。继续？')) return;
      await this.recipeAdminAction(editor, async () => { editor.execution = await api.post(`${versionPath(editor)}/test`, { route_id: Number(editor.routeId) || 0, expected_revision: read(editor.recipe, 'revision') }); editor.forceAcknowledged = false; });
    },
    canForceRecipe() {
      const editor = this.recipeEditor, execution = editor?.execution;
      return !!(execution && !read(execution, 'success') && read(execution, 'final') && read(execution, 'sent_at_ms') > 0 && !['none', 'ignored'].includes(read(execution, 'error_class')) && !read(execution, 'expected_cancel') && editor.forceAcknowledged && !editor.conflict && !editor.busy);
    },
    async publishRecipe(force = false) {
      const owner = this.profiles;
      const editor = this.recipeEditor;
      if (!editor?.selected || !editor.execution || editor.busy || editor.conflict || editor.dirty) return;
      if (force ? !this.canForceRecipe() : !read(editor.execution, 'success')) return;
      if (!confirm(force ? '该测试失败。确认仍将此版本设为自动探活配方？Force 不会跳过配置身份与版本校验。' : '将该成功测试版本发布到所选作用域？')) return;
      await this.recipeAdminAction(editor, async () => {
        editor.recipe = await api.post(`${recipePath(editor)}/versions/${editor.selected.id}/publish`, { expected_revision: read(editor.recipe, 'revision'), test_execution_id: read(editor.execution, 'id'), force });
        if (this.profiles !== owner) return;
        this.clearRecipeEvidence(); this.msg = force ? '已显式强制发布；失败测试记录保留' : '已发布测试版本'; await this.loadRecipes(true);
      });
    },
    async retireRecipe(action) {
      const owner = this.profiles;
      const editor = this.recipeEditor; if (!editor || !['disable', 'archive'].includes(action)) return;
      if (!confirm(action === 'archive' ? '归档后该配方不再参与解析，不能继续编辑或发布。确认归档？' : '停用该配方并恢复较低优先级模板？')) return;
      await this.recipeAdminAction(editor, async () => { editor.recipe = await api.post(`${recipePath(editor)}/${action}`, { expected_revision: read(editor.recipe, 'revision') }); if (this.profiles !== owner) return; this.clearRecipeEvidence(); await this.loadRecipes(true); });
    },
    previewCost(preview) {
      if (!preview) return '';
      const input = preview.input_bound_known ? `输入估算 0–${preview.input_token_upper_bound}` : '输入无可证上界（正文含 Secret）';
      const output = preview.output_bound_known ? `输出最多 ${preview.output_token_upper_bound}` : '输出未声明可证上界';
      return `${input} · ${output} token；估算不等于账单`;
    },

    async loadProfiles(reset = true) {
      const state = this.profiles;
      if (this.profiles.loading) return;
      this.profiles.loading = true;
      try {
        const query = new URLSearchParams({ limit: '25' });
        for (const [key, value] of Object.entries(this.profileFilters)) if (String(value).trim()) query.set(key, value);
        if (!reset && this.profiles.next_cursor) query.set('cursor', this.profiles.next_cursor);
        const page = await api.get('/client-probe-profiles?' + query);
        if (this.profiles !== state) return;
        this.profiles.items = reset ? page.items : [...this.profiles.items, ...page.items]; this.profiles.next_cursor = page.next_cursor || '';
      } catch (error) { if (this.profiles === state) { this.err = error.message; if (error.status === 400) state.next_cursor = ''; } }
      finally { state.loading = false; }
    },
    async openClientProfile(id) {
      const owner = this.profiles;
      try {
        const profile = await api.get('/client-probe-profiles/' + id);
        if (this.profiles !== owner) return;
        this.profileView = { profile, routeId: '', preview: null, execution: null, busy: false, conflict: false }; this._lockModal?.(() => this.closeClientProfile()); this.$nextTick?.(() => focusFirst(this.$refs?.clientProfileDialog));
      } catch (error) { if (this.profiles === owner) this.err = error.message; }
    },
    closeClientProfile() { if (this.profileView?.busy) return; this.profileView = null; this._unlockModal?.(); },
    async previewClientProfile() {
      const view = this.profileView; if (!view) return;
      await this.recipeAdminAction(view, async () => { view.preview = await api.post(`/client-probe-profiles/${view.profile.id}/preview`, { route_id: Number(view.routeId) || 0 }); view.execution = null; });
    },
    async testClientProfile() {
      const owner = this.profiles;
      const view = this.profileView;
      if (!view?.preview || view.profile.status !== 'candidate' || !this.canRunCandidate()) return;
      if (!confirm('发送一次真实测试（可能消耗 token）。成功后启用此候选作为 fallback，并替换同站同端点的旧 tested profile；失败仍为 candidate。继续？')) return;
      await this.recipeAdminAction(view, async () => { view.execution = await api.post(`/client-probe-profiles/${view.profile.id}/test`, { route_id: Number(view.routeId) || 0, expected_revision: view.profile.revision }); if (this.profiles !== owner) return; view.profile = await api.get('/client-probe-profiles/' + view.profile.id); if (this.profiles !== owner) return; await this.loadProfiles(true); });
    },
    async disableClientProfile() {
      const owner = this.profiles;
      const view = this.profileView; if (!view || !confirm('停用此 Profile？历史测试记录会保留。')) return;
      await this.recipeAdminAction(view, async () => { view.profile = await api.post(`/client-probe-profiles/${view.profile.id}/disable`, { expected_revision: view.profile.revision }); if (this.profiles !== owner) return; view.preview = null; view.execution = null; await this.loadProfiles(true); });
    },
  });
  const originalReset = shell.reset;
  shell.reset = function reset() {
    const result = originalReset?.call(this);
    this.recipeEditor = null; this.profileView = null; this.recipeCandidateSeed = null;
    this.profiles = emptyPage(); this.profileFilters = emptyProfileFilters(); this._unlockModal?.();
    if (this.recipes?.filter) Object.assign(this.recipes.filter, { upstream_id: '', route_id: '', endpoint: '', status: '' });
    return result;
  };
  if (Array.isArray(shell.tabs) && !shell.tabs.some(tab => tab.id === 'client-profiles')) shell.tabs.push({ id: 'client-profiles', name: '客户端形状' });
  return shell;
}
