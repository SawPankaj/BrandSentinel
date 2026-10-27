const test = require('node:test');
const assert = require('node:assert/strict');
const { runChecks, canApprove, recheck } = require('../frontend/core.js');

test('clean copy returns no findings', () => {
  assert.deepEqual(runChecks('Explore flexible learning options with our career support team.'), []);
});

test('absolute outcome claims are high severity, source-labelled and never auto-resolved', () => {
  const [finding] = runChecks('We guarantee 100% placement for all students.');
  assert.equal(finding.kind, 'Unsupported claim');
  assert.equal(finding.severity, 'High');
  assert.match(finding.source, /Claims library/);
  assert.equal(finding.status, 'Open');
});

test('preferred terminology flags each occurrence with a suggested correction', () => {
  const findings = runChecks('Students can learn. Our students are welcome.');
  assert.equal(findings.length, 2);
  assert.ok(findings.every(f => f.kind === 'Terminology' && f.suggestion === 'learners'));
});

test('inaccessible generic link text produces an accessibility finding', () => {
  const [finding] = runChecks('Click here to view our programme.');
  assert.equal(finding.kind, 'Accessibility');
  assert.equal(finding.severity, 'Low');
  assert.match(finding.source, /Accessibility rule pack/);
});

test('tone cues are labelled rule-based and remain open for human review', () => {
  const [finding] = runChecks('This course helps you achieve your dreams.');
  assert.equal(finding.kind, 'Tone of voice');
  assert.equal(finding.method, 'Rule-based');
  assert.equal(finding.status, 'Open');
});

test('multiple check types can be returned together without losing evidence', () => {
  const findings = runChecks('Students can achieve your dreams. Click here.');
  assert.deepEqual(findings.map(f => f.kind), ['Terminology', 'Accessibility', 'Tone of voice']);
  assert.ok(findings.every(f => f.quote && f.reason && f.source && f.confidence > 0));
});

test('approval is blocked while any finding is open or awaiting a reviewer', () => {
  assert.equal(canApprove([{ status: 'Open' }]), false);
  assert.equal(canApprove([{ status: 'Escalated' }]), false);
});

test('approval is available only after every finding has a human decision', () => {
  assert.equal(canApprove([{ status: 'Accepted' }, { status: 'Dismissed', note: 'Not applicable' }, { status: 'Reviewer cleared', note: 'Evidence checked' }]), true);
  assert.equal(canApprove([]), true);
});

test('claims and unverified facts require an authorised reviewer clearance even after creator action', () => {
  assert.equal(canApprove([{ kind: 'Unsupported claim', status: 'Accepted' }]), false);
  assert.equal(canApprove([{ kind: 'Unverified fact', status: 'Dismissed', note: 'Not applicable' }]), false);
  assert.equal(canApprove([{ kind: 'Unsupported claim', status: 'Reviewer cleared' }]), true);
});

test('approved structured glossary rules drive terminology checks', () => {
  const knowledge = [{ category: 'Terminology', title: 'Customer terminology', source: 'Glossary v3', bannedTerm: 'customers', preferredTerm: 'members' }];
  const [finding] = runChecks('Our customers come first.', knowledge);
  assert.equal(finding.kind, 'Terminology');
  assert.equal(finding.suggestion, 'members');
  assert.match(finding.source, /Glossary v3/);
});

test('unsupported measurable statements are marked unverified without approved evidence', () => {
  const [finding] = runChecks('The course takes 12 weeks.');
  assert.equal(finding.kind, 'Unverified fact');
  assert.match(finding.source, /No matching entry/);
});

test('approved fact evidence prevents an unverified flag for a matching quantity', () => {
  const knowledge = [{ category: 'Approved facts', detail: 'Course duration is 12 weeks.' }];
  assert.deepEqual(runChecks('The course takes 12 weeks.', knowledge), []);
});

test('resubmission keeps prior decisions and adds newly detected findings', () => {
  const prior = [{ id: 'f1', kind: 'Terminology', quote: 'students', status: 'Accepted' }];
  const next = recheck(prior, 'Students can enroll for 12 weeks.');
  assert.equal(next[0].status, 'Accepted');
  assert.ok(next.some(f => f.kind === 'Unverified fact' && f.status === 'Open'));
});

test('resubmission does not duplicate a still open matching finding', () => {
  const prior = runChecks('Students can enroll.');
  const next = recheck(prior, 'Students can enroll.');
  assert.equal(next.filter(f => f.kind === 'Terminology').length, 1);
});

test('document accessibility checks are preserved with evidence and deduplicated against text checks', () => {
  const sourceChecks = [{ kind: 'Accessibility', severity: 'High', quote: '<img>', reason: 'Image alt text is missing.', source: 'Accessibility rule pack · Image alternative text', suggestion: 'Add concise alternative text.' }];
  const findings = runChecks('A campaign image is attached.', [], sourceChecks);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].source, sourceChecks[0].source);
  assert.equal(findings[0].status, 'Open');
});
