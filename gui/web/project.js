/* Project policies choose once; preview and build share the server's plan. */
(function(root) {
  const clone = value => JSON.parse(JSON.stringify(value));
  const backendNames = ['karity', 'classic', 'mov', 'bare'];
  function rowsToTree(rows) {
    const tree = {children: new Map()};
    for (const row of rows) {
      let node = tree;
      const parts = row.path.split('/');
      parts.forEach((part, i) => {
        if (!node.children.has(part)) node.children.set(part, {name: part, path: parts.slice(0, i + 1).join('/'), children: new Map()});
        node = node.children.get(part);
        if (i === parts.length - 1) node.row = row;
      });
    }
    return tree;
  }
  function backendLabel(row, actual) {
    if (row.kind === 'resource') return row.status === 'copied' ? 'Copied' : actual ? 'Not copied' : 'Copy';
    if (!actual && row.status === 'discovered') return 'Not checked';
    if (actual && row.status !== 'success') return 'Not Applied';
    if (actual && row.vm_applied === false) return 'No VM';
    if (actual && row.backend === 'mixed') return 'Mixed';
    const name = row.backend || row.planned_backend;
    return name === 'mov' ? 'MOV' : name ? name[0].toUpperCase() + name.slice(1) : 'No VM';
  }
  function attach({api, bootstrap, getConfig, tr = value => value, isSingleBusy = () => false}) {
    const $ = id => document.getElementById(id);
    const panel = $('project-panel');
    let documentConfig = null, base = '', preview = null, plan = null, report = null;
    let selected = '', active = false, busy = false, checking = false, revision = 0, timer = null;
    let refreshTask = null, queued = false, previewError = '';
    const collapsed = new Set(), states = new Map();
    const presetNames = ['custom', ...Object.keys(bootstrap.profiles || {}).filter(name => name.startsWith('builtin:'))];
    const el = (tag, text, cls) => { const node = document.createElement(tag); if (text != null) node.textContent = text; if (cls) node.className = cls; return node; };
    const status = (message, detail = '', tone = 'info') => {
      $('project-status').textContent = tr(message);$('project-progress').textContent = detail;$('project-feedback').dataset.state = tone;
    };
    const presetLabel = name => !name ? '—' : name === 'custom' ? tr('Current settings') : name.startsWith('builtin:') ? name.slice(8) : `${name} (${tr('Project')})`;
    function fillSelect(select, values, first = null) {
      select.replaceChildren();
      if (first !== null) select.add(new Option(tr(first), ''));
      for (const name of values) select.add(new Option(select.id.includes('preset') ? presetLabel(name) : backendLabel({backend:name}, false), name));
    }
    function initialDocument() {
      return {...clone(getConfig()), project: {root: '', output: '', entry: '', include: ['**/*.lua'], exclude: ['**/.git/**'],
        preset_selection: {mode:'fixed', value:'custom'}, backend_selection: {mode:'fixed', value:getConfig().vm_options?.backend || 'karity'}, module_overrides: {}}};
    }
    function populate() {
      const project = documentConfig.project;
      for (const key of ['root', 'output', 'entry']) $('project-' + key).value = project[key] ?? '';
      for (const key of ['include', 'exclude']) $('project-' + key).value = (project[key] || (key === 'include' ? ['**/*.lua'] : ['**/.git/**'])).join('\n');
      $('project-copy-resources').checked = Boolean(project.copy_resources);
      for (const kind of ['preset', 'backend']) {
        const policy = project[kind + '_selection'] || {mode:'default'};
        const choices = [...new Set([...(kind === 'preset' ? [...presetNames, ...Object.keys(documentConfig.profiles || {})] : backendNames), ...Object.keys(policy.weights || {}), ...(policy.value ? [policy.value] : [])])];
        fillSelect($('project-' + kind + '-value'), choices);
        $('project-' + kind + '-value').value = policy.value || choices[0];
        $('project-' + kind + '-mode').value = policy.mode;
        const container = $('project-' + kind + '-weights');container.replaceChildren();
        for (const name of choices) {
          const label = el('label', kind === 'preset' ? presetLabel(name) : backendLabel({backend:name}, false));
          const input = el('input');input.type = 'number';input.min = '0';input.step = 'any';input.dataset.choice = name;
          input.setAttribute('aria-label', `${name} weight`);
          input.value = String(policy.weights?.[name] ?? (policy.mode === 'weighted' ? 0 : name === 'custom' ? 0 : 1));
          input.addEventListener('input', changed);label.append(input);container.append(label);
        }
        policyVisibility(kind);
      }
      render();
    }
    function policyVisibility(kind) {
      const weighted = $('project-' + kind + '-mode').value === 'weighted';
      $('project-' + kind + '-value').hidden = $('project-' + kind + '-mode').value !== 'fixed';
      $('project-' + kind + '-weights').hidden = !weighted;
    }
    function readFields() {
      const project = documentConfig.project;
      for (const key of ['root', 'output', 'entry']) project[key] = $('project-' + key).value;
      for (const key of ['include', 'exclude']) project[key] = $('project-' + key).value.split(/\r?\n/).filter(Boolean);
      project.copy_resources = $('project-copy-resources').checked;
      for (const kind of ['preset', 'backend']) {
        const mode = $('project-' + kind + '-mode').value;
        if (mode === 'default') delete project[kind + '_selection'];
        else project[kind + '_selection'] = mode === 'fixed' ? {mode, value:$('project-' + kind + '-value').value}
          : {mode, weights:Object.fromEntries([...$('project-' + kind + '-weights').querySelectorAll('input')].map(input => [input.dataset.choice, Number(input.value)]))};
      }
    }
    function changed() {
      if (busy) return;
      readFields();revision++;plan = null;report = null;previewError = '';checking = true;states.clear();$('project-result-code').hidden = true;render();
      clearTimeout(timer);status('Updating preview…', '', 'busy');timer = setTimeout(refresh, 250);
    }
    async function prepare(snapshot, token) {
      if (!snapshot.project.root) { preview = null;selected = '';status('Choose a project folder to start.');render();return; }
      status('Finding project files…', '', 'busy');
      try {
        const found = await api.discover_project({document:snapshot, base});
        if (token !== revision) return;
        if (!found.ok) { preview = null;throw new Error(found.error); }
        preview = found.files;
        if (!preview.modules.some(row => row.path === selected)) selected = preview.modules[0]?.path || preview.resources[0]?.path || '';
        $('project-entry-options').replaceChildren(...preview.modules.map(row => new Option(row.path, row.path)));
        render();
        if (!preview.modules.length) throw new Error(tr('No Lua files match the include/exclude patterns.'));
        if (!snapshot.project.output) { status('Choose an output folder to build.', `${preview.modules.length} Lua · ${preview.resources.length} ${tr('resources')}`);return; }
        status('Checking project settings…', `${preview.modules.length} Lua · ${preview.resources.length} ${tr('resources')}`, 'busy');
        const value = await api.preview_project({document:snapshot, base});
        if (token !== revision) return;
        if (!value.ok) throw new Error(value.error);
        preview = value.plan;plan = value.plan;
        const presetFilter = $('project-filter-preset'), filter = presetFilter.value;
        fillSelect(presetFilter, [...new Set(preview.modules.map(row => row.preset))].sort(), 'All presets');presetFilter.value = filter;
        if (!plan.valid) {
          const invalid = plan.modules.find(row => !row.compatibility.valid);selected = invalid.path;
          previewError = `${invalid.path}: ${invalid.compatibility.error}`;
          status('Resolve module errors before building', previewError, 'error');
        } else status('Ready to build', `${plan.modules.length} Lua · ${plan.resources.length} ${tr('resources')}`, 'ready');
        render();
      } catch (error) {
        if (token === revision) {
          previewError = error.message || String(error);
          if (previewError.startsWith('Entry is missing or excluded:')) {
            $('project-file-options').open = true;
            previewError = `${tr('Entry not found. Choose a listed Lua file, or clear it for a module-only folder.')} (${snapshot.project.entry})`;
          }
          status('Check project settings', previewError, 'error');render();
        }
      }
    }
    async function refresh() {
      if (busy) return;
      clearTimeout(timer);timer = null;
      readFields();revision++;plan = null;report = null;previewError = '';checking = true;queued = true;
      states.clear();$('project-result-code').hidden = true;render();
      if (refreshTask) return refreshTask;
      // One request pair at a time. Rapid edits replace queued work, rather
      // than building a backlog behind Python's build lock.
      refreshTask = (async () => {
        while (queued) { queued = false;await prepare(clone(documentConfig), revision); }
      })();
      try { await refreshTask; }
      finally { refreshTask = null;checking = timer !== null;render(); }
    }
    function rows() {
      if (!preview) return [];
      const actual = new Map((report?.modules || []).concat(report?.resources || []).map(row => [row.path, row]));
      return preview.modules.concat(preview.resources).map(row => ({...row, ...actual.get(row.path),
        status:actual.get(row.path)?.status || states.get(row.path) || row.status}));
    }
    function renderTree() {
      const all = rows(), query = $('project-search').value.toLowerCase(), backend = $('project-filter-backend').value;
      const preset = $('project-filter-preset').value, failed = $('project-failed-only').checked;
      const visible = all.filter(row => (!query || row.path.toLowerCase().includes(query)) && (!preset || row.preset === preset || row.planned_preset === preset)
        && (!backend || (backend === 'none' ? row.vm_applied === false : (row.backend || row.planned_backend) === backend))
        && (!failed || ['failed','invalid'].includes(row.status)));
      const target = $('project-tree');target.replaceChildren();
      function append(parent, tree) {
        for (const node of [...tree.children.values()].sort((a,b) => Number(Boolean(a.row)) - Number(Boolean(b.row)) || a.name.localeCompare(b.name))) {
          if (!node.row) {
            const folder = el('details');folder.open = !collapsed.has(node.path);
            folder.append(el('summary', node.name));folder.addEventListener('toggle', () => folder.open ? collapsed.delete(node.path) : collapsed.add(node.path));
            append(folder, node);parent.append(folder);continue;
          }
          const row = node.row, button = el('button', null, 'project-file');button.type = 'button';button.dataset.path = row.path;
          button.classList.toggle('selected', selected === row.path);button.dataset.status = row.status;
          button.setAttribute('aria-label', row.path);button.setAttribute('aria-pressed', String(selected === row.path));
          button.append(el('span', node.name, 'project-file-name'), el('span', tr(backendLabel(row, Boolean(report))), 'project-tag'));
          if (row.kind !== 'resource') button.append(el('span', presetLabel(row.preset || row.planned_preset), 'project-tag'));
          const selection = row.selection || {}, reason = !Object.keys(selection).length ? '—' : Object.values(selection).includes('override') ? 'Override' : Object.values(selection).includes('weighted') ? 'Weighted' : 'Fixed';
          button.append(el('span', row.kind === 'resource' ? '' : tr(reason), 'project-selection'), el('span', tr(row.status), 'project-file-status'));
          if (row.compatibility?.warnings?.length || row.compatibility?.error) button.append(el('span', '!', 'project-warning-mark'));
          button.addEventListener('click', () => { selected = row.path;$('project-result-code').hidden = true;render(); });parent.append(button);
        }
      }
      append(target, rowsToTree(visible));
      if (!visible.length) target.append(el('p', tr(!preview ? 'Choose a project folder to start.' : all.length ? 'No files match the current filters.' : 'No Lua files match the include/exclude patterns.'), 'project-empty'));
      const counts = {};
      for (const row of all.filter(row => row.kind !== 'resource')) { const label = backendLabel(row, Boolean(report));counts[label] = (counts[label] || 0) + 1; }
      $('project-counts').textContent = preview ? `${tr(preview.discovery_only ? 'Files found' : !plan ? 'Preview outdated' : report ? 'Applied' : 'Planned')}: ${Object.entries(counts).map(([name,n]) => `${tr(name)} ${n}`).join(' · ')} · ${visible.length}/${all.length}` : tr('Choose a project folder to start.');
    }
    function renderDetail() {
      const row = rows().find(row => row.path === selected), values = $('project-detail-values');values.replaceChildren();
      $('project-override').hidden = !row || row.kind === 'resource';$('project-view-output').disabled = busy || !report?.published || !row || row.kind === 'resource' || row.status !== 'success';
      if (!row) {
        $('project-detail-name').textContent = tr('Module details');$('project-detail-summary').textContent = tr('Select a file in the tree.');
        $('project-warning-details').hidden = true;$('project-dependencies').replaceChildren();return;
      }
      $('project-detail-name').textContent = row.path;
      $('project-detail-summary').textContent = `${tr(backendLabel(row, Boolean(report)))} · ${tr(row.status)}`;
      const overrides = documentConfig.project.module_overrides?.[row.path] || {};
      fillSelect($('project-module-preset'), [...new Set([...presetNames, ...Object.keys(documentConfig.profiles || {}), row.planned_preset || row.preset, overrides.preset])].filter(Boolean), 'Use project settings');
      fillSelect($('project-module-backend'), [...new Set([...backendNames, overrides.backend])].filter(Boolean), 'Use project settings');
      $('project-module-preset').value = overrides.preset || '';$('project-module-backend').value = overrides.backend || '';
      const details = {'Output path':row.output || row.path, 'Preset':presetLabel(row.preset || row.planned_preset),
        'Lua target':row.target?.lua_version || row.effective_config?.target?.lua_version || documentConfig.target?.lua_version || '5.3',
        'Planned backend':row.planned_backend || row.backend || '—', 'Selection':Object.entries(row.selection || {}).map(([k,v]) => `${k}: ${v}`).join(' · '),
        'Source bytes':row.input_bytes ?? '—', 'Output bytes':row.output_bytes ?? '—', 'Build time':row.elapsed == null ? '—' : `${row.elapsed.toFixed(3)} s`,
        'Passes':(row.executed_passes || row.effective_config?.passes || []).join(', ') || '—'};
      if (report) details.Published = row.published ? 'Yes' : 'No';
      for (const [name, value] of Object.entries(details)) values.append(el('dt', tr(name)), el('dd', String(value)));
      const warnings = [...(row.compatibility?.warnings || []), row.compatibility?.error, row.error].filter(Boolean);
      $('project-detail-warnings').textContent = warnings.join('\n');
      const warningDetails = $('project-warning-details');warningDetails.hidden = !warnings.length;
      if (warningDetails.dataset.path !== row.path || row.error || row.compatibility?.error) warningDetails.open = Boolean(row.error || row.compatibility?.error);
      warningDetails.dataset.path = row.path;$('project-warning-summary').textContent = `${tr('Warnings')} ${warnings.length}`;
      const dependencies = $('project-dependencies');dependencies.replaceChildren(el('strong', tr('Dependencies')));
      for (const reference of row.dependencies?.requires || []) dependencies.append(el('div', `${reference.module || 'require(…)'} · ${reference.status}${reference.path ? ' → ' + reference.path : ''}`));
      if (!row.dependencies?.requires?.length) dependencies.append(el('p', tr('No static requires.'), 'project-muted'));
    }
    function updateControls() {
      panel.querySelectorAll('.project-settings input, .project-settings textarea, .project-settings button, .project-policies select, .project-policies input, .project-policies button, #project-override select, #project-override button, #project-load, #project-save').forEach(node => node.disabled = busy);
      const ready = !checking && plan?.valid, project = documentConfig?.project;
      const label = busy ? 'Building project…' : !project?.root ? 'Choose a project folder' : !project?.output ? 'Choose an output folder'
        : checking ? 'Checking project settings…' : ready ? 'Build project →' : 'Check project settings';
      $('project-build').disabled = busy || !ready;$('project-build').textContent = tr(label);
      $('project-build').title = previewError || tr(label);
      $('project-tree').setAttribute('aria-busy', String(checking));
      $('single-mode').disabled = busy;$('project-mode').disabled = busy;
    }
    function render() { renderTree();renderDetail();updateControls(); }
    function setMode(project) {
      if (busy || isSingleBusy()) return;
      active = project;document.documentElement.dataset.workMode = project ? 'project' : 'single';panel.hidden = !project;
      $('single-mode').setAttribute('aria-pressed', String(!project));$('project-mode').setAttribute('aria-pressed', String(project));
      if (project && !documentConfig) { documentConfig = initialDocument();populate();status('Choose a project folder to start.'); }
    }
    function override(kind) {
      if (!selected || busy) return;
      documentConfig.project.module_overrides ||= {};
      const value = $('project-module-' + kind).value, entry = documentConfig.project.module_overrides[selected] ||= {};
      if (value) entry[kind] = value;else delete entry[kind];
      if (!Object.keys(entry).length) delete documentConfig.project.module_overrides[selected];changed();
    }
    async function load() {
      if (busy) return;
      const result = await api.load_project();if (!result) return;
      if (!result.ok) return status('Open failed', result.error);
      documentConfig = result.document;base = result.base;populate();await refresh();
    }
    async function save() {
      if (busy || !documentConfig) return;
      readFields();const result = await api.save_project({document:clone(documentConfig), base});if (!result) return;
      if (!result.ok) return status('Save failed', result.error);
      documentConfig = result.document;base = result.base;populate();await refresh();
    }
    async function build() {
      if (busy) return;
      if (checking) return;
      if (!plan?.valid) return refresh();
      clearTimeout(timer);timer = null;
      const fixedPlan = plan;busy = true;report = null;states.clear();$('project-result-code').hidden = true;
      const total = fixedPlan.modules.length + fixedPlan.resources.length;
      $('project-progress-bar').max = Math.max(1,total);$('project-progress-bar').value = 0;render();status('Building project…', '', 'busy');
      try {
        const run = await api.start_build({mode:'project',plan_id:fixedPlan.plan_id,document:clone(documentConfig)});
        if (!run.ok) throw new Error(run.error);
        let cursor = 0;
        while (true) {
          const progress = await api.poll_build(run.id,cursor);if (!progress.ok) throw new Error(progress.error);cursor = progress.cursor;
          for (const event of progress.events) {
            const copy = event.phase.startsWith('project-copy:'), module = event.phase.startsWith('project:');
            if (!copy && !module) continue;
            const path = event.phase.slice(copy ? 13 : 8);
            if (module && path === 'publish') { status('Publishing project…', '', 'busy');continue; }
            states.set(path,event.status === 'running' ? 'building' : event.status === 'success' ? copy ? 'copied' : 'success' : 'failed');
            status('Building project…',path,'busy');
          }
          $('project-progress-bar').value = [...states.values()].filter(value => ['success','copied','failed'].includes(value)).length;render();
          if (progress.done) break;
          await new Promise(resolve => setTimeout(resolve,150));
        }
        const result = await api.get_build_result(run.id);report = result.report || null;
        if (!result.ok) { status('Build failed; output not published', result.error || report?.error || '', 'error');return; }
        $('project-progress-bar').value = total;$('project-config').open = false;
        status('Project completed', `${fixedPlan.output} · ${result.elapsed.toFixed(2)} s`, 'ready');
      } catch (error) { status('Build status unavailable',error.message || String(error),'error'); }
      finally { busy = false;render(); }
    }
    $('single-mode').addEventListener('click', () => setMode(false));$('project-mode').addEventListener('click', () => setMode(true));
    for (const key of ['root','output','entry','include','exclude','copy-resources']) $('project-' + key).addEventListener('input',changed);
    for (const kind of ['preset','backend']) {
      $('project-' + kind + '-mode').addEventListener('change', () => { policyVisibility(kind);changed(); });
      $('project-' + kind + '-value').addEventListener('change',changed);
      $('project-module-' + kind).addEventListener('change', () => override(kind));
    }
    for (const id of ['project-search','project-filter-backend','project-filter-preset','project-failed-only']) $(id).addEventListener('input',renderTree);
    $('project-preview').addEventListener('click',refresh);$('project-build').addEventListener('click',build);
    $('project-load').addEventListener('click',load);$('project-save').addEventListener('click',save);
    $('project-reroll').addEventListener('click', () => { documentConfig.project.seed = [...crypto.getRandomValues(new Uint32Array(4))].join('-');changed(); });
    $('project-current').addEventListener('click', () => {
      const profiles = documentConfig.profiles;
      documentConfig = {...clone(getConfig()), ...(profiles ? {profiles} : {}), project:{...documentConfig.project,preset_selection:{mode:'fixed',value:'custom'}}};
      populate();changed();
    });
    $('project-clear-override').addEventListener('click', () => { delete documentConfig.project.module_overrides?.[selected];changed(); });
    for (const kind of ['root','output']) $('project-pick-' + kind).addEventListener('click', async () => {
      const value = await api.pick_project_folder(kind);if (!value?.path) return;
      $('project-' + kind).value = value.path;
      if (kind === 'root' && !$('project-output').value) $('project-output').value = value.path.replace(/[\\/]+$/,'') + '.protected';changed();
    });
    $('project-view-output').addEventListener('click', async () => {
      const result = await api.read_project_output({plan_id:preview.plan_id,path:selected});
      if (!result.ok) return status('Cannot read output',result.error);
      $('project-result-code').textContent = result.content;$('project-result-code').hidden = false;
    });
    $('language-select').addEventListener('change', () => queueMicrotask(() => { if (active) render(); }));
    return {active:() => active, build, load, save, render, notice:message => status(message)};
  }
  root.ProjectMode = {attach, rowsToTree, backendLabel};
  if (typeof module !== 'undefined' && module.exports) module.exports = root.ProjectMode;
})(typeof window === 'undefined' ? globalThis : window);
