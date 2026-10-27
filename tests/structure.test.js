const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ROOT = path.resolve(__dirname, '..');
const FRONTEND = path.join(ROOT, 'frontend');

test('app shell has unique IDs and references all local assets', () => {
  const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(ids).size, ids.length, 'HTML IDs must be unique');
  for (const asset of ['styles.css', 'core.js', 'app.js']) assert.ok(html.includes(asset), `${asset} must be loaded`);
});

test('stylesheet is self-contained with balanced blocks', () => {
  const css = fs.readFileSync(path.join(FRONTEND, 'styles.css'), 'utf8');
  assert.equal((css.match(/{/g) || []).length, (css.match(/}/g) || []).length);
  assert.doesNotMatch(css, /https?:\/\//, 'the demo should not request external styles or fonts');
});

test('essential workflows are present in the UI event map', () => {
  const app = fs.readFileSync(path.join(FRONTEND, 'app.js'), 'utf8');
  const html = fs.readFileSync(path.join(FRONTEND, 'index.html'), 'utf8');
  for (const action of ['submit-review', 'accept-finding', 'edit-finding', 'dismiss-finding', 'escalate-finding', 'clear-escalation', 'approve-review', 'save-rule', 'save-source', 'save-resubmission', 'add-comment', 'show-versions', 'save-workspace', 'export-audit']) {
    assert.ok(app.includes(`'${action}'`), `${action} should be wired`);
  }
  assert.match(html, /id="login-form"/);
  assert.match(app, /X-CSRF-Token/);
  assert.doesNotMatch(app, /localStorage|X-Workspace-ID|DEMO_ROLES/);
});
