/* migration.mjs — P1 full_url NeedsReview confirm UI (§19.2).
 * Does not modify dirty app.js.
 */

export function createMigrationFeature(shell, api) {
  shell.confirmEndpointReview = async function confirmEndpointReview(ep) {
    const id = this.f(ep, 'id', 'ID');
    const rev = this.f(ep, 'revision', 'Revision') || 0;
    const override = window.prompt(
      '确认审核：请粘贴该 Endpoint 的完整 URL（不得猜测多协议映射）',
      this.f(ep, 'url_override', 'URLOverride') || ''
    );
    if (override == null) return;
    const url = String(override).trim();
    if (!url) {
      this.err = 'url_override 不能为空';
      return;
    }
    try {
      this.busy = true;
      this.err = '';
      await api.post('/upstream-endpoints/' + id + '/confirm-review', {
        url_override: url,
        expected_revision: rev,
      });
      this.msg = 'Endpoint #' + id + ' 已确认审核并转为 canonical';
      if (typeof this.loadEndpoints === 'function') await this.loadEndpoints(true);
    } catch (e) {
      this.err = e && e.message ? e.message : String(e);
    } finally {
      this.busy = false;
    }
  };
}
