const $ = (id) => document.getElementById(id),
  el = (tag, text) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = text;
    return n;
  },
  pretty = (v) => JSON.stringify(v, null, 2);
let state = null,
  examples = [],
  decision = null,
  comparison = null,
  busy = false;
function status(s) {
  $('status').textContent = s;
}
function tab(name) {
  for (const n of document.querySelectorAll('.panel')) n.hidden = n.id !== name;
  for (const b of document.querySelectorAll('[data-tab]')) {
    const active = b.dataset.tab === name;
    b.classList.toggle('active', active);
    if (active) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  }
}
for (const b of document.querySelectorAll('[data-tab]'))
  b.addEventListener('click', () => tab(b.dataset.tab));
function lock(value) {
  busy = value;
  for (const n of document.querySelectorAll('button,input,select,textarea')) n.disabled = value;
}
async function api(path, value) {
  const response = await fetch(
    path,
    value === undefined
      ? {}
      : {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(value),
        },
  );
  const data = await response.json();
  if (!response.ok) throw Error(data.error || `Request failed (${response.status}).`);
  return data;
}
async function task(fn) {
  if (busy) return;
  lock(true);
  try {
    await fn();
  } catch (e) {
    status(e.message);
  } finally {
    lock(false);
  }
}
function invalidateDecision() {
  decision = null;
  $('decision-word').textContent = '—';
  $('decision-reason').textContent = 'Inputs changed. Evaluate again.';
  $('decision-origin').textContent = '';
  $('decision-export').hidden = true;
  $('explanation').hidden = true;
}
function invalidateComparison() {
  comparison = null;
  $('comparison').hidden = true;
}
function request() {
  return {
    action: $('action').value.trim(),
    roles: $('roles')
      .value.split(',')
      .map((x) => x.trim())
      .filter(Boolean),
    subject: JSON.parse($('subject').value),
    resource: JSON.parse($('resource').value),
  };
}
function fillRequest(r) {
  $('action').value = r.action;
  $('roles').value = r.roles.join(', ');
  $('subject').value = pretty(r.subject);
  $('resource').value = pretty(r.resource);
  invalidateDecision();
}
function renderState() {
  $('head-label').textContent = `${state.head.policy.name} / revision ${state.head.id}`;
  $('expected').textContent =
    `Publication expects head revision ${state.head.id}. A stale edit is rejected rather than overwriting another revision.`;
  $('history-count').textContent = `/ ${state.total} total`;
  for (const id of ['decision-revision', 'load-revision', 'before', 'after']) {
    const select = $(id),
      old = select.value;
    select.replaceChildren();
    if (id === 'decision-revision') {
      const opt = el('option', 'Unsaved draft');
      opt.value = 'draft';
      select.append(opt);
    }
    for (const r of state.history) {
      const opt = el('option', `Revision ${r.id}${r.id === state.head.id ? ' · current' : ''}`);
      opt.value = r.id;
      select.append(opt);
    }
    select.value = [...select.options].some((o) => o.value === old) ? old : String(state.head.id);
  }
  $('history').replaceChildren();
  for (const r of state.history) {
    const row = el('tr');
    for (const text of [r.id, r.note, r.created, r.digest.slice(0, 14)]) row.append(el('td', text));
    $('history').append(row);
  }
}
async function refresh() {
  state = await api('/api/state');
  renderState();
}
function renderDecision() {
  $('decision-word').textContent = decision.decision.toUpperCase();
  $('decision-card').classList.toggle('deny', decision.decision === 'deny');
  $('decision-reason').textContent = {
    'explicit-deny': 'A matching deny rule takes precedence.',
    'matching-allow': 'At least one allow rule matches, with no matching deny.',
    'default-deny': 'No allow rule matches this request.',
  }[decision.reason];
  $('decision-origin').textContent = decision.draft
    ? 'Preview of unsaved draft. No revision was created.'
    : `Revision ${decision.revision} · digest ${decision.digest.slice(0, 18)}…`;
  $('decision-export').hidden = false;
  $('explanation').hidden = false;
  $('rules').replaceChildren();
  for (const r of decision.rules) {
    const details = el('details'),
      summary = el('summary', `${r.id} / ${r.effect}`),
      badge = el('span', r.matched ? 'MATCHED' : 'NO MATCH');
    badge.className = 'badge' + (r.matched ? ' matched' : '');
    summary.append(badge);
    details.append(summary);
    const table = el('table'),
      head = el('tr');
    for (const v of ['Check', 'Actual', 'Expected', 'Result']) head.append(el('th', v));
    const thead = el('thead');
    thead.append(head);
    table.append(thead);
    const body = el('tbody');
    for (const c of r.checks) {
      const row = el('tr');
      for (const text of [
        c.check + (c.op ? ' ' + c.op : ''),
        c.present === false ? '(missing)' : JSON.stringify(c.actual),
        JSON.stringify(c.expected),
        c.matched ? 'match' : 'no match',
      ]) {
        const cell = el('td');
        cell.append(el('code', text));
        row.append(cell);
      }
      body.append(row);
    }
    table.append(body);
    const scroll = el('div');
    scroll.className = 'scroll';
    scroll.append(table);
    details.append(scroll);
    $('rules').append(details);
  }
  if (!decision.rules.length)
    $('rules').append(el('p', 'The policy contains no rules. Default deny applies.'));
}
async function evaluate() {
  const r = request(),
    selected = $('decision-revision').value;
  decision =
    selected === 'draft'
      ? await api('/api/preview', { policy: JSON.parse($('draft').value), request: r })
      : await api('/api/decide', { revision: Number(selected), request: r });
  decision = { ...decision, request: r };
  renderDecision();
  status('Decision evaluated. Expand a rule to inspect each check.');
}
$('evaluate').addEventListener('click', () => task(evaluate));
for (const id of ['action', 'roles', 'subject', 'resource'])
  $(id).addEventListener('input', invalidateDecision);
$('decision-revision').addEventListener('change', invalidateDecision);
$('example').addEventListener('change', () => fillRequest(examples[Number($('example').value)]));
$('draft').addEventListener('input', () => {
  if ($('decision-revision').value === 'draft') invalidateDecision();
  status('Draft edited. Preview it before creating a revision.');
});
$('refresh').addEventListener('click', () =>
  task(async () => {
    await refresh();
    status('Head refreshed. Your draft is unchanged; review it before creating a revision.');
  }),
);
$('load').addEventListener('click', () =>
  task(async () => {
    const r = await api('/api/revisions/' + $('load-revision').value);
    $('draft').value = pretty(r.policy);
    $('note').value = `Restore policy from revision ${r.id}`;
    if ($('decision-revision').value === 'draft') invalidateDecision();
    status(`Revision ${r.id} loaded into the draft. History is unchanged.`);
  }),
);
$('preview-draft').addEventListener('click', () =>
  task(async () => {
    $('decision-revision').value = 'draft';
    invalidateDecision();
    await evaluate();
    tab('desk');
  }),
);
$('publish').addEventListener('click', () =>
  task(async () => {
    const old = state.head.id,
      r = await api('/api/revisions', {
        expected: old,
        policy: JSON.parse($('draft').value),
        note: $('note').value,
      });
    await refresh();
    $('note').value = '';
    $('decision-revision').value = r.id;
    $('before').value = old;
    $('after').value = r.id;
    invalidateDecision();
    invalidateComparison();
    status(`Created revision ${r.id}. Compare it with revision ${old} in Change review.`);
  }),
);
function download(name, data) {
  const url = URL.createObjectURL(new Blob([pretty(data)], { type: 'application/json' })),
    a = el('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('draft-export').addEventListener('click', () =>
  task(async () => {
    const policy = JSON.parse($('draft').value);
    await api('/api/preview', { policy, request: examples[0] });
    download('policy-weave-policy.json', policy);
    status('Validated draft exported.');
  }),
);
$('decision-export').addEventListener('click', () => {
  if (decision) download('policy-weave-decision.json', decision);
});
$('file').addEventListener('change', () =>
  task(async () => {
    const file = $('file').files[0];
    try {
      if (!file) return;
      if (file.size > 150000) throw Error('Policy imports are limited to 150 KB.');
      const policy = JSON.parse(await file.text());
      await api('/api/preview', { policy, request: examples[0] });
      $('draft').value = pretty(policy);
      if ($('decision-revision').value === 'draft') invalidateDecision();
      status('Policy imported into the draft. No revision was created.');
    } finally {
      $('file').value = '';
    }
  }),
);
for (const id of ['before', 'after']) $(id).addEventListener('change', invalidateComparison);
$('suite').addEventListener('input', invalidateComparison);
$('compare').addEventListener('click', () =>
  task(async () => {
    comparison = await api('/api/compare', {
      before: Number($('before').value),
      after: Number($('after').value),
      requests: JSON.parse($('suite').value),
    });
    $('comparison').hidden = false;
    $('comparison-summary').textContent =
      `${comparison.changed} of ${comparison.total} outcomes changed`;
    $('comparison-rows').replaceChildren();
    for (const r of comparison.rows) {
      const row = el('tr');
      if (r.changed) row.className = 'changed';
      row.append(
        el(
          'td',
          `${r.index + 1}. ${r.request.action} / ${r.request.roles.join(', ') || 'no roles'}`,
        ),
      );
      for (const side of ['before', 'after']) {
        const cell = el('td', r[side].decision.toUpperCase()),
          note = el(
            'span',
            r[side].reason +
              ` · allow: ${r[side].allows.join(', ') || 'none'} · deny: ${r[side].denies.join(', ') || 'none'}`,
          );
        note.className = 'result-note';
        cell.append(note);
        row.append(cell);
      }
      row.append(el('td', r.changed ? 'yes' : 'no'));
      const cell = el('td'),
        button = el('button', 'Inspect after');
      button.setAttribute('aria-label', `Inspect request ${r.index + 1} after`);
      button.addEventListener('click', () =>
        task(async () => {
          fillRequest(r.request);
          $('decision-revision').value = comparison.after;
          await evaluate();
          tab('desk');
        }),
      );
      cell.append(button);
      row.append(cell);
      $('comparison-rows').append(row);
    }
    status('Comparison complete. Outcome changes and both sets of matching rules are shown.');
  }),
);
$('comparison-export').addEventListener('click', () => {
  if (comparison) download('policy-weave-comparison.json', comparison);
});
task(async () => {
  const values = await Promise.all([api('/api/state'), api('/api/examples')]);
  state = values[0];
  examples = values[1].requests;
  renderState();
  $('draft').value = pretty(state.head.policy);
  $('suite').value = pretty(examples);
  fillRequest(examples[1]);
  if (state.history.length > 1) $('before').value = state.history[1].id;
  await evaluate();
});
