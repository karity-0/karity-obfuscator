/* Details live off the main canvas. All actions use the existing app/state APIs. */
(function(root) {
  const clone = value => JSON.parse(JSON.stringify(value));
  const stable = value => JSON.stringify(value, (_, v) => v && !Array.isArray(v) && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
  function configChanges(before, after, prefix = '') {
    const result = [];
    for (const key of new Set([...Object.keys(before || {}), ...Object.keys(after || {})])) {
      const a = before?.[key], b = after?.[key], path = prefix + key;
      if (stable(a) === stable(b)) continue;
      if (a && b && !Array.isArray(a) && !Array.isArray(b) && typeof a === 'object' && typeof b === 'object')
        result.push(...configChanges(a, b, path + '.'));
      else result.push({path, before: a, after: b});
    }
    return result;
  }
  function markerEdit(source, start, end, kind, options = '') {
    const selected = source.slice(start, end);
    const macro = /^(STRING|NUMBER|BOOLEAN|TABLE)_OBF$/.test(kind);
    if ((macro || kind.endsWith('_START')) && !selected.trim()) throw new Error('Select code in the editor first.');
    if (/[\r\n]/.test(options)) throw new Error('Keep options on a single line.');
    options = options.trim();
    if (options.startsWith('(') && options.endsWith(')')) options = options.slice(1, -1);
    let replacement;
    if (macro) replacement = `${kind}(${selected})`;
    else {
      if (kind === 'VM') { start = 0; end = 0; }
      else {
        start = start > 0 ? source.lastIndexOf('\n', start - 1) + 1 : 0;
        if (kind.endsWith('_START')) {
          const next = source.indexOf('\n', end - (source[end - 1] === '\n' ? 1 : 0));
          end = next < 0 ? source.length : next + 1;
        } else end = start;
      }
      const indent = source.slice(start).match(/^[\t ]*/)[0];
      replacement = `${indent}--@${kind}${options ? `(${options})` : ''}\n`;
      if (kind.endsWith('_START')) {
        const body = source.slice(start, end);
        replacement += body + (body.endsWith('\n') ? '' : '\n');
        replacement += `${indent}--@${kind.replace(/_START$/, '_END')}\n`;
      }
    }
    return {start, end, replacement};
  }
  const serializeOptions = options => Object.entries(options).map(([key, value]) => `${key}=${JSON.stringify(value)}`).join(', ');
  function sameBuild(a, b) {
    return ['source_hash', 'config_hash', 'preset', 'backend'].every(key => a?.[key] === b?.[key])
      && stable(a?.checks) === stable(b?.checks);
  }

  function attach(ctx) {
    const $ = id => document.getElementById(id), {ui, tr} = ctx;
    const element = (tag, text, className) => {
      const el = document.createElement(tag);
      if (text !== undefined) el.textContent = text;
      if (className) el.className = className;
      return el;
    };
    const modalOpen = () => Boolean(document.querySelector('dialog[open]')) || !$('preferences-overlay').classList.contains('hidden');
    const openers = new WeakMap();
    let running = false, closed = false, stages = new Map(), lastAttempt, lastSuccess, previousSuccess;
    let buildElapsed = 0, clock, dismissed = false, lastKind, markerRevision = 0, markerTimer, validated = null, markerPending = false;
    let commandIndex = 0, commandMatches = [];
    const presetDialog = $('preset-picker'), inspector = $('build-inspector'), palette = $('command-palette');
    const byteText = value => `${Number(value).toLocaleString()} B`;
    const timeText = value => `${Number(value).toFixed(2)} s`;
    const backendName = value => ({classic:'Classic',karity:'Karity',mov:'MOV'})[value] || value;

    function closeOtherDialogs() {
      document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
      if (!$('preferences-overlay').classList.contains('hidden')) ctx.closePreferences();
      $('marker-tools').open = false;
    }
    function openDialog(dialog, from = document.activeElement) {
      closeOtherDialogs(); openers.set(dialog, from);
      dialog.showModal();
    }
    for (const dialog of [presetDialog, inspector, palette]) {
      dialog.addEventListener('click', event => { if (event.target === dialog) dialog.close(); });
      dialog.addEventListener('close', () => {
        const target = openers.get(dialog); openers.delete(dialog);
        if (modalOpen()) return;
        if (target?.isConnected && target.getClientRects().length) target.focus();
        else $('command-open').focus();
      });
    }
    $('preset-picker-close').addEventListener('click', () => presetDialog.close());
    $('inspector-close').addEventListener('click', () => inspector.close());
    $('command-close').addEventListener('click', () => palette.close());
    $('inspect-output').addEventListener('click', openInspector);
    $('preset-details').addEventListener('click', event => openPresets(event.currentTarget));
    $('backend-details').addEventListener('click', event => { closeOtherDialogs(); ctx.openBackendPicker(event.currentTarget); });
    for (const [id, selector, open] of [
      ['quick-presets', '[data-preset]', openPresets],
      ['quick-backends', '[data-backend]', button => { closeOtherDialogs(); ctx.openBackendPicker(button); }],
    ]) {
      $(id).addEventListener('contextmenu', event => {
        const button = event.target.closest(selector);
        if (!button) return;
        event.preventDefault(); open(button);
      });
      $(id).addEventListener('keydown', event => {
        if (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10')) {
          event.preventDefault(); open(event.target.closest(selector) || $(id));
        }
      });
    }
    presetDialog.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
      const cards = [...presetDialog.querySelectorAll('[data-preset-choice]')], index = cards.indexOf(document.activeElement);
      if (index < 0) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? cards.length - 1
        : (index + (['ArrowRight', 'ArrowDown'].includes(event.key) ? 1 : -1) + cards.length) % cards.length;
      cards[next].focus();
    });

    function openPresets(from) {
      renderPresets(); openDialog(presetDialog, from);
      (presetDialog.querySelector('[aria-pressed="true"]') || presetDialog.querySelector('[data-preset-choice]')).focus();
    }
    function renderPresets() {
      const {profiles, user_presets, preset_revision, passes, vm_options} = ctx.getBootstrap();
      const state = ctx.getState();
      const focused = document.activeElement?.dataset.presetChoice;
      const descriptions = [
        'VM first. Protect key code with markers.',
        'Light source protection, balanced cost.',
        'Strings and control flow protected throughout.',
        'Deeper transformations, with packing.',
      ];
      const motifs = [
        {path:'M16 64H112 M46 44L66 64 46 84 M76 44L96 64 76 84', nodes:[[16,64],[112,64]]},
        {path:'M16 64L48 32 80 64 112 32 M16 64L48 96 80 64 112 96', nodes:[[16,64],[48,32],[48,96],[80,64],[112,32],[112,96]]},
        {path:'M16 64L48 24 80 44 112 64 80 84 48 104 16 64 M48 24V104 M80 44V84 M16 64H112', nodes:[[16,64],[48,24],[48,104],[80,44],[80,84],[112,64]]},
        {path:'M16 76L64 100 112 76 M16 60L64 84 112 60 M16 44L64 20 112 44 64 68Z M64 68V100', nodes:[[16,44],[64,20],[112,44],[64,100]]},
      ];
      $('preset-picker-title').textContent = tr('Choose a protection preset');
      $('preset-picker-note').textContent = tr('Your VM backend and target stay unchanged.');
      $('preset-picker-close').textContent = tr('Close') + ' · Esc';
      $('preset-picker-hint').textContent = tr('Click to select · Arrow keys to navigate');
      const cards = $('preset-cards'); cards.replaceChildren();
      user_presets.forEach((name, index) => {
        const next = root.PresetState.applyPreset(state, name, profiles[name], preset_revision);
        const changes = configChanges(state.config, next.config);
        const article = element('article', undefined, 'preset-detail-card');
        const button = element('button', undefined, 'preset-detail-choice');
        button.type = 'button'; button.dataset.presetChoice = name;
        button.setAttribute('aria-pressed', String(state.preset === name));
        const top = element('span', undefined, 'backend-card-top');
        top.append(element('span', tr(index < 2 ? 'Selective protection' : 'Whole-source protection'), 'backend-kind'),
          element('span', tr('Currently selected'), 'backend-current'));
        const artwork = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        artwork.setAttribute('viewBox', '0 0 128 128'); artwork.setAttribute('aria-hidden', 'true');
        artwork.classList.add('preset-artwork');
        const path = document.createElementNS(artwork.namespaceURI, 'path');
        path.setAttribute('d', motifs[index].path); artwork.append(path);
        for (const [x,y] of motifs[index].nodes) {
          const circle = document.createElementNS(artwork.namespaceURI, 'circle');
          circle.setAttribute('cx', x); circle.setAttribute('cy', y); circle.setAttribute('r', 4);
          artwork.append(circle);
        }
        button.append(top, artwork, element('strong', ctx.presetLabel(name), 'backend-name'),
          element('span', tr(descriptions[index]), 'backend-description'));
        const vm = next.config.vm_options || {};
        const backend = ctx.getBootstrap().backend_aliases[vm.backend] || vm.backend || 'karity';
        const unsupported = vm_options.filter(field => field.resolution[backend]?.outcome === 'disable' && vm[field.name]);
        const fallback = vm_options.filter(field => field.resolution[backend]?.outcome === 'fallback' && vm[field.name]);
        const label = pass => tr(passes.find(p => p.name === pass)?.label || pass);
        const notices = element('span', undefined, 'preset-notices');
        if (unsupported.length || fallback.length) notices.append(element('span', `${backendName(backend)} · ${tr(unsupported.length ? 'Support limitations' : 'Fallback implementation')}`, 'capability-warning'));
        if (next.preset_custom) notices.append(element('span', tr('Saved custom settings'), 'capability-warning'));
        button.append(notices);
        button.addEventListener('click', () => { ctx.applyPreset(name); presetDialog.close(); });
        const details = element('details', undefined, 'preset-diff');
        details.append(element('summary', tr('Details')));
        const body = element('div', undefined, 'preset-diff-body');
        body.append(element('p', `${tr('Source & main')}: ${next.config.passes.map(label).join(' · ')}`),
          element('p', `${tr('VM output')}: ${next.config.vm_output_passes.map(label).join(' · ')}`),
          element('p', `${tr('VM count')}: ${vm.vm_count} · ${tr('Block variants')}: ${vm.block_variant_count}`));
        if (next.preset_custom) body.append(element('p', tr('Restores your saved custom settings.'), 'capability-warning'));
        if (unsupported.length) body.append(element('p', `${tr('Support limitations')}: ${unsupported.map(field=>tr(field.label)).join(', ')}`, 'capability-warning'));
        if (fallback.length) body.append(element('p', `${tr('Fallback implementation')}: ${fallback.map(field=>`${field.name} → ${field.resolution[backend].target}`).join(', ')}`, 'capability-warning'));
        if (!changes.length) body.append(element('p', tr('No configuration changes.')));
        for (const change of changes) {
          const row = element('div', undefined, 'config-difference');
          row.append(element('strong', change.path), element('span', `${JSON.stringify(change.before) ?? '—'} → ${JSON.stringify(change.after) ?? '—'}`));
          body.append(row);
        }
        details.append(body); article.append(button, details); cards.append(article);
      });
      if (focused) cards.querySelector(`[data-preset-choice="${focused}"]`)?.focus();
    }

    const markerHints = {
      STRING_OBF: 'Select a string literal → insert', NUMBER_OBF: 'Select a number literal → insert',
      BOOLEAN_OBF: 'Select true / false → insert', TABLE_OBF: 'Select a table { … } → insert',
      VM_START: 'Select complete statements → VM region', FUNCTION_OBF: 'Insert before a function',
      FUNCTION_OBF_START: 'Select statements inside a function → protect', VM: 'Insert at the start of the file',
      NO_VM: 'Insert before a function → exclude VM', NO_VM_START: 'Select statements → exclude VM',
      NO_OBF_START: 'Select statements → exclude protection',
    };
    const hasOptions = kind => ['VM', 'VM_START', 'FUNCTION_OBF', 'FUNCTION_OBF_START'].includes(kind);
    const fields = kind => {
      if (!hasOptions(kind)) return [];
      if (kind.startsWith('FUNCTION')) return ctx.getBootstrap().marker_fields.function_obf;
      return [{name: 'profile', label: 'Preset', kind: 'enum', common: true,
        choices: Object.keys(ctx.getBootstrap().profiles)}, ...ctx.getBootstrap().marker_fields.vm];
    };
    function makeField(field) {
      const row = element('label', undefined, 'marker-field'); row.dataset.markerField = field.name;
      row.append(element('span', tr(field.label)));
      let input;
      if (field.kind === 'boolean' || field.kind === 'enum') {
        input = element('select', undefined, 'select-control');
        input.add(new Option(tr('Inherit'), ''));
        const choices = field.kind === 'boolean' ? [true, false] : field.choices;
        for (const value of choices) input.add(new Option(field.kind === 'boolean' ? tr(value ? 'On' : 'Off')
          : field.name === 'profile' ? ctx.presetLabel(value) : field.name === 'backend' ? backendName(value) : tr(String(value)), String(value)));
      } else {
        input = element('input', undefined, 'text-control'); input.type = 'number';
        input.min = field.min ?? ''; input.max = field.max ?? ''; input.step = field.step ?? 1;
        input.placeholder = tr('Inherit');
      }
      input.dataset.markerOption = field.name;
      input.addEventListener('change', async () => {
        const chosen = input.value;
        const validation = await validateMarker();
        if (!validation.ok) return;
        const options = {...validation.options};
        if (chosen === '') delete options[field.name];
        else options[field.name] = field.kind === 'boolean' ? chosen === 'true'
          : field.kind === 'enum' ? chosen : Number(chosen);
        if (field.name === 'boundary_mode' && chosen === 'split') options.cff = true;
        $('marker-options').value = serializeOptions(options);
        await validateMarker();
      });
      row.append(input); return row;
    }
    function markerChanged() {
      const kind = $('marker-kind').value;
      if (lastKind !== kind) {
        lastKind = kind; validated = null; markerRevision++; markerPending = false;
        clearTimeout(markerTimer); $('marker-options').value = '';
      }
      const common = $('marker-fields'), advanced = $('marker-advanced-fields');
      const focused = document.activeElement?.dataset.markerOption;
      common.replaceChildren(); advanced.replaceChildren();
      for (const field of fields(kind)) (field.common ? common : advanced).append(makeField(field));
      $('marker-advanced').hidden = !hasOptions(kind);
      $('marker-options').hidden = !hasOptions(kind); $('marker-options-label').hidden = !hasOptions(kind);
      $('marker-options').placeholder = kind.startsWith('FUNCTION') ? 'cff=true, junk=false' : 'profile="builtin:fast", junk_rate=0.05';
      $('marker-hint').textContent = tr(markerHints[kind]);
      $('marker-preview').setAttribute('aria-label', tr('Marker preview'));
      syncFields(); previewMarker();
      if (focused) document.querySelector(`[data-marker-option="${focused}"]`)?.focus();
      if ($('marker-tools').open && hasOptions(kind)) scheduleValidation();
    }
    function syncFields() {
      const kind = $('marker-kind').value;
      const options = validated?.options || {}, effective = validated?.effective || ctx.getState().config.vm_options;
      const backend = ctx.getBootstrap().backend_aliases[effective?.backend] || effective?.backend || 'karity';
      for (const field of fields(kind)) {
        const row = document.querySelector(`[data-marker-field="${field.name}"]`), input = row.querySelector('input,select');
        input.value = Object.hasOwn(options, field.name) ? String(options[field.name]) : '';
        const disabled = !kind.startsWith('FUNCTION') && field.resolution?.[backend]?.outcome === 'disable';
        input.disabled = Boolean(disabled); row.classList.toggle('unsupported-option', Boolean(disabled));
        row.title = disabled ? `${tr('Not used by this backend; stored value retained.')} (${backend})`
          : field.resolution?.[backend]?.outcome === 'fallback' ? `${tr('Fallback implementation')}: ${field.resolution[backend].target}` : '';
      }
    }
    function previewMarker() {
      try {
        const edit = markerEdit(ui.input.value, ui.input.selectionStart, ui.input.selectionEnd,
          $('marker-kind').value, hasOptions($('marker-kind').value) ? $('marker-options').value : '');
        $('marker-preview').textContent = edit.replacement;
        $('insert-marker-btn').disabled = markerPending || (hasOptions($('marker-kind').value) && validated?.ok === false);
      } catch (error) {
        $('marker-preview').textContent = tr(error.message); $('insert-marker-btn').disabled = true;
      }
    }
    function scheduleValidation() {
      clearTimeout(markerTimer);
      markerRevision++; markerPending = true; previewMarker();
      markerTimer = setTimeout(validateMarker, 180);
    }
    async function validateMarker() {
      clearTimeout(markerTimer);
      const revision = ++markerRevision, kind = $('marker-kind').value, text = $('marker-options').value;
      markerPending = true; previewMarker();
      let result;
      try { result = await ctx.getApi().validate_marker_options({kind, options: text, config: clone(ctx.getState().config)}); }
      catch (error) { result = {ok: false, error: String(error)}; }
      if (revision !== markerRevision || kind !== $('marker-kind').value || text !== $('marker-options').value) return {ok: false};
      markerPending = false; validated = result;
      let hint = result.ok ? tr(markerHints[kind]) : tr(result.error || 'Invalid marker options');
      if (result.ok && kind.startsWith('VM')) {
        const backend = ctx.getBootstrap().backend_aliases[result.effective.backend] || result.effective.backend;
        hint += ` · ${tr('Effective VM backend')}: ${backendName(backend)}`;
        const ignored = fields(kind).filter(field => Object.hasOwn(result.options, field.name)
          && field.resolution?.[backend]?.outcome === 'disable');
        if (ignored.length) hint += ` · ${tr('Support limitations')}: ${ignored.map(field=>tr(field.label)).join(', ')}`;
      }
      $('marker-hint').textContent = hint;
      syncFields(); previewMarker(); return result;
    }
    $('marker-options').addEventListener('input', scheduleValidation);
    ui.input.addEventListener('select', previewMarker);
    ui.input.addEventListener('input', previewMarker);
    async function insertMarker() {
      const kind = $('marker-kind').value;
      if (hasOptions(kind) && !(await validateMarker()).ok) return;
      try {
        const edit = markerEdit(ui.input.value, ui.input.selectionStart, ui.input.selectionEnd, kind,
          hasOptions(kind) ? $('marker-options').value : '');
        ui.input.focus(); ui.input.setRangeText(edit.replacement, edit.start, edit.end, 'select');
        ui.input.dispatchEvent(new Event('input', {bubbles: true}));
        $('marker-tools').open = false;
        ctx.refreshEditors();
        ctx.setStatus('Marker inserted', 'success', kind);
      } catch (error) { $('marker-hint').textContent = tr(error.message); }
    }

    const phaseNames = {
      configuration: 'Configuration validation', selection: 'Protection markers',
      'vm:compile': 'Lua compilation', 'vm:ir': 'VM intermediate representation',
      'vm:optimize': 'VM optimization', 'vm:protection': 'VM protection',
      'vm:synthesis': 'Opcode synthesis',
      'vm:lowering': 'Backend lowering', 'vm:generation': 'VM generation',
      'vm:serialization': 'Serialization', 'vm:graphs': 'Runtime graphs',
      'vm:integrity': 'Integrity finalization', 'output:transforms': 'Output transformations',
      'vm:encryption': 'Bytecode encryption', 'finalization:runtime': 'Finalization',
      'finalization:signature': 'Output signature',
      'source:parse_treesitter': 'Source parsing', 'source:parse_lua': 'Source parsing',
      'output:parse_treesitter': 'Output parsing', 'output:parse_lua': 'Output parsing',
    };
    function phaseLabel(name) {
      if (phaseNames[name]) return tr(phaseNames[name]);
      const [scope, ...rest] = name.split(':');
      const namePart = rest.join(':');
      if (namePart === 'VMPass') return tr('VM generation');
      return `${tr(scope === 'source' ? 'Source protection' : scope === 'post' ? 'Finalization' : 'Output transformations')} · ${passLabel(namePart)}`;
    }
    function passLabel(name) {
      if (name === 'OutputSignaturePass') return tr('Output signature');
      const meta = ctx.getBootstrap().passes.find(pass=>pass.class_name===name);
      return tr(meta?.label || name.replace(/Pass$/, '').replace(/([a-z])([A-Z])/g, '$1 $2'));
    }
    function renderProgress() {
      const panel = $('build-progress'); panel.hidden = dismissed || (!running && !lastAttempt);
      panel.setAttribute('aria-label', tr('Build status'));
      panel.dataset.state = running ? 'running' : lastAttempt?.ok ? 'success' : 'error';
      let title = panel.querySelector('.build-stage');
      if (!title) {
        const row = element('div', undefined, 'build-progress-head');
        title = element('strong', '', 'build-stage'); title.setAttribute('aria-live', 'polite');
        const elapsed = element('span', '', 'build-elapsed');
        const details = element('button', '', 'button tiny ghost'); details.type = 'button'; details.id = 'build-details';
        details.addEventListener('click', openInspector); row.append(title, elapsed, details);
        const dismiss = element('button', '×', 'button tiny ghost'); dismiss.id = 'build-dismiss'; dismiss.type = 'button';
        dismiss.addEventListener('click', () => { dismissed = true; renderProgress(); }); row.append(dismiss);
        panel.append(row, element('ol', undefined, 'build-stages'));
      }
      const active = [...stages.values()].filter(event => event.status === 'running').at(-1);
      const text = running ? (active ? phaseLabel(active.phase) : tr('Starting…'))
        : lastAttempt?.ok ? tr('Protection complete') : `${tr('Build failed')}${lastAttempt?.failed_phase ? ' · '+phaseLabel(lastAttempt.failed_phase) : ''}`;
      if (title.textContent !== text) title.textContent = text;
      panel.querySelector('.build-elapsed').textContent = timeText(buildElapsed);
      const details = $('build-details'); details.textContent = tr(running ? 'Details' : 'Result inspector');
      $('build-dismiss').hidden = running; $('build-dismiss').setAttribute('aria-label', tr('Close'));
      const list = panel.querySelector('.build-stages'); list.replaceChildren();
      if (running) for (const event of [...stages.values()].filter(e => e.status !== 'running').slice(-2)) {
        list.append(element('li', `${event.status === 'success' ? '✓' : '×'} ${phaseLabel(event.phase)} · ${timeText(event.elapsed || 0)}`));
      }
      else if (lastAttempt?.ok) list.append(element('li', `${byteText(lastAttempt.metadata.source_bytes)} → ${byteText(lastAttempt.metadata.output_bytes)} · ${Number(lastAttempt.metadata.size_ratio).toFixed(2)}×`));
      else list.append(element('li', String(lastAttempt?.error || '').trim().split('\n').at(-1), 'build-error'));
      $('inspect-output').disabled = !lastAttempt && !running;
    }
    async function runBuild(payload) {
      running = true; dismissed = false; stages = new Map(); lastAttempt = null; buildElapsed = 0; renderProgress();
      let cursor = 0;
      try {
        const start = await ctx.getApi().start_build(clone(payload));
        if (!start.ok) throw new Error(start.error);
        clock = setInterval(() => { renderProgress(); if (inspector.open) renderInspector(); }, 250);
        while (!closed) {
          let poll;
          try { poll = await ctx.getApi().poll_build(start.id, cursor); }
          catch (error) { await new Promise(resolve => setTimeout(resolve, 800)); continue; }
          if (!poll.ok) throw new Error(poll.error);
          cursor = poll.cursor; buildElapsed = poll.elapsed;
          for (const event of poll.events) stages.set(event.id, event);
          renderProgress();
          if (poll.done) {
            const result = await ctx.getApi().get_build_result(start.id);
            buildElapsed = result.build_elapsed ?? buildElapsed;
            lastAttempt = result;
            if (result.ok) {
              previousSuccess = lastSuccess;
              // Keep metadata and profiling, not another copy of a large output.
              lastSuccess = {...result}; delete lastSuccess.output;
            }
            return result;
          }
          await new Promise(resolve => setTimeout(resolve, 180));
        }
        throw new Error('Builder closed');
      } catch (error) {
        lastAttempt = {ok: false, error: String(error)}; return lastAttempt;
      } finally {
        running = false; clearInterval(clock); renderProgress(); if (inspector.open) renderInspector();
      }
    }
    function openInspector() { renderInspector(); openDialog(inspector); $('inspector-close').focus(); }
    function renderInspector() {
      $('inspector-title').textContent = tr(running ? 'Build details' : 'Result inspector');
      $('inspector-close').textContent = tr('Close') + ' · Esc';
      const body = $('inspector-body'); body.replaceChildren();
      if (running) {
        body.append(element('p', `${tr('Build elapsed time')}: ${timeText(buildElapsed)}`));
        const list = element('ol', undefined, 'inspector-stages');
        for (const event of stages.values()) list.append(element('li', `${event.status === 'success' ? '✓' : event.status === 'error' ? '×' : '…'} ${phaseLabel(event.phase)}${event.elapsed === undefined ? '' : ' · '+timeText(event.elapsed)}`));
        body.append(list); return;
      }
      if (lastAttempt && !lastAttempt.ok) {
        body.append(element('p', `${tr('Build failed')}${lastAttempt.failed_phase ? ' · '+phaseLabel(lastAttempt.failed_phase) : ''}`, 'build-error'),
          element('pre', lastAttempt.error, 'inspector-error'));
        if (stages.size) {
          const trace = element('details', undefined, 'profile-detail');
          trace.append(element('summary', tr('Build stages')));
          const list = element('ol', undefined, 'inspector-stages');
          for (const event of stages.values()) list.append(element('li', `${event.status === 'success' ? '✓' : '×'} ${phaseLabel(event.phase)} · ${timeText(event.elapsed || 0)}`));
          trace.append(list); body.append(trace);
        }
        if (lastSuccess) body.append(element('p', tr('Previous successful result'), 'inspector-notice'));
      }
      if (!lastSuccess) return;
      const m = lastSuccess.metadata, values = element('dl', undefined, 'result-metrics');
      for (const [name, value] of [
        ['Original source size', byteText(m.source_bytes)], ['Obfuscated output size', byteText(m.output_bytes)],
        ['Size ratio', m.size_ratio == null ? '—' : `${m.size_ratio.toFixed(2)}×`],
        ['Build elapsed time', timeText(lastSuccess.build_elapsed ?? lastSuccess.elapsed)],
        ['Preset', ctx.presetLabel(m.preset) + (m.preset_custom ? ' · '+tr('Custom settings') : '')],
        ['VM backend', backendName(m.backend)], ['Lua target', `Lua ${m.target.lua_version || '5.3'} · ${m.target.environment || 'standalone'}`],
        ['Characters', `${m.source_characters.toLocaleString()} → ${m.output_characters.toLocaleString()}`],
      ]) values.append(element('dt', tr(name)), element('dd', value));
      body.append(values);
      if (previousSuccess) {
        const previous = previousSuccess.metadata;
        body.append(element('h3', tr('Previous build comparison')),
          element('p', tr(sameBuild(m, previous) ? 'Same input and settings' : 'Different build conditions'), 'inspector-notice'));
        if (!sameBuild(m, previous)) {
          const differences = [];
          if (m.source_hash !== previous.source_hash) differences.push(tr('Source'));
          if (m.preset !== previous.preset) differences.push(tr('Preset'));
          if (m.backend !== previous.backend) differences.push(tr('VM backend'));
          if (stable(m.target) !== stable(previous.target)) differences.push(tr('Lua target'));
          if (m.config_hash !== previous.config_hash || stable(m.checks) !== stable(previous.checks)) differences.push(tr('Settings'));
          body.append(element('p', differences.join(' · ')));
        }
        const delta = m.output_bytes - previous.output_bytes;
        const elapsedDelta = (lastSuccess.build_elapsed ?? lastSuccess.elapsed) - (previousSuccess.build_elapsed ?? previousSuccess.elapsed);
        body.append(element('p', `${tr('Output')}: ${delta >= 0 ? '+' : ''}${byteText(delta)} · ${tr('Build elapsed time')}: ${elapsedDelta >= 0 ? '+' : ''}${timeText(elapsedDelta)}`));
      }
      if (lastSuccess.warnings?.length) {
        body.append(element('h3', tr('Support limitations')));
        lastSuccess.warnings.forEach(warning => body.append(element('p', warning, 'capability-warning')));
      }
      const profile = lastSuccess.profile;
      const phases = (profile?.passes || []).flatMap(pass => pass.details || []);
      const selected = phases.filter(phase => phase.phase === 'synthesis_cost_selection');
      const synthesis = selected.length ? selected : phases.filter(phase => phase.phase === 'opcode_synthesis');
      const physical = phases.filter(phase => phase.phase === 'synthesis_physical');
      if (synthesis.length) {
        const sum = (records, key) => records.reduce((total, record) => total + (record[key] || 0), 0);
        body.append(element('h3', tr('Opcode synthesis')),
          element('p', `${tr('Recipes')}: ${sum(synthesis, 'recipes')} · ${tr('Synthesized regions')}: ${sum(physical, 'regions')} · ${tr('Handlers')}: ${sum(physical, 'handlers')} · ${tr('Fallback regions')}: ${sum(physical, 'fallback_regions') + selected.reduce((n, phase) => n + (phase.decisions || []).filter(d => d.fallback).length, 0)}`));
      }
      if (profile?.passes?.length) {
        body.append(element('h3', tr('Profiling details')), element('p', `${tr('Profiled pass time')}: ${timeText(profile.total_elapsed)}`));
        for (const pass of profile.passes) {
          const details = element('details', undefined, 'profile-detail');
          details.append(element('summary', `${pass.step} · ${passLabel(pass.name)} · ${timeText(pass.elapsed)}`));
          details.addEventListener('toggle', () => {
            if (details.open && !details.querySelector('pre')) details.append(element('pre', JSON.stringify(pass, null, 2)));
          });
          body.append(details);
        }
      }
    }

    const commands = () => [
      {name: 'Change protection preset', description: 'Choose a protection preset', action: () => openPresets($('command-open'))},
      {name: 'Choose VM backend', description: 'Choose the VM that runs your code.', action: () => ctx.openBackendPicker($('command-open'))},
      {name: 'Insert Marker', description: 'Insert protection markers around selected code', action: () => { $('source-view').click(); $('marker-tools').open = true; markerChanged(); $('marker-kind').focus(); }},
      {name: 'Open GUI Preferences', description: 'GUI preferences', action: ctx.openPreferences},
      {name: 'Change Theme', description: 'Theme', action: () => { ctx.openPreferences(); ctx.selectPreferenceTab('appearance'); $('appearance-tab').focus(); }},
      {name: 'Run Source', description: 'Source', shortcut: 'F5', enabled: Boolean(ui.input.value.trim()) && !executionBusy(), action: () => ctx.executeCode('source')},
      {name: 'Run Output', description: 'Output', shortcut: 'Shift F5', enabled: Boolean(ui.output.value) && !executionBusy(), action: () => ctx.executeCode('output')},
      {name: 'Obfuscate', description: 'Build settings', enabled: !ui.run.disabled && Boolean(ui.input.value.trim()), action: ctx.runObfuscation},
      {name: 'Save Configuration', description: 'Save configuration', action: ctx.saveConfiguration},
      {name: 'Copy Output', description: 'Protected output copied to clipboard.', enabled: Boolean(ui.output.value), action: ctx.copyOutput},
      {name: 'Show Result Inspector', description: 'Result inspector', enabled: running || Boolean(lastAttempt), action: openInspector},
    ];
    const executionBusy = () => !$('execution-stop').disabled;
    function openCommands() {
      $('command-query').value = ''; commandIndex = 0; renderCommands();
      openDialog(palette, $('command-open')); $('command-query').focus();
    }
    $('command-open').addEventListener('click', openCommands);
    document.addEventListener('keydown', event => {
      if (event.isComposing || !(event.ctrlKey || event.metaKey) || event.altKey || event.shiftKey || event.key.toLowerCase() !== 'k') return;
      event.preventDefault();
      if (palette.open) { palette.close(); return; }
      if (modalOpen()) return;
      openCommands();
    });
    $('command-query').addEventListener('input', () => { commandIndex = 0; renderCommands(); });
    palette.addEventListener('keydown', event => {
      if (!['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter'].includes(event.key) || event.isComposing) return;
      if (event.target !== $('command-query')) return;
      event.preventDefault();
      if (event.key === 'Enter') { executeCommand(commandIndex); return; }
      if (!commandMatches.length) return;
      commandIndex = event.key === 'Home' ? 0 : event.key === 'End' ? commandMatches.length - 1
        : (commandIndex + (event.key === 'ArrowDown' ? 1 : -1) + commandMatches.length) % commandMatches.length;
      highlightCommand();
    });
    function executeCommand(index) {
      const command = commandMatches[index]; if (!command || command.enabled === false) return;
      palette.close(); command.action();
    }
    function highlightCommand() {
      [...$('command-results').children].forEach((row, index) => row.setAttribute('aria-selected', String(index === commandIndex)));
      const selected = $('command-results').children[commandIndex];
      if (selected) { $('command-query').setAttribute('aria-activedescendant', selected.id); selected.scrollIntoView({block: 'nearest'}); }
      else $('command-query').removeAttribute('aria-activedescendant');
    }
    function renderCommands() {
      const query = $('command-query').value.toLowerCase().trim().split(/\s+/).filter(Boolean);
      commandMatches = commands().filter(command => query.every(part => `${command.name} ${tr(command.name)} ${command.description} ${tr(command.description)} ${root.GuiI18n.tr(command.name, 'ko')} ${root.GuiI18n.tr(command.description, 'ko')}`.toLowerCase().includes(part)));
      const list = $('command-results'); list.replaceChildren();
      commandMatches.forEach((command, index) => {
        const row = element('li'); row.id = `command-result-${index}`; row.setAttribute('role', 'option');
        row.setAttribute('aria-disabled', String(command.enabled === false));
        const text = element('span'); text.append(element('strong', tr(command.name)), element('small', tr(command.enabled === false ? 'Unavailable in the current state' : command.description)));
        row.append(text); if (command.shortcut) row.append(element('kbd', command.shortcut));
        row.addEventListener('click', () => executeCommand(index)); list.append(row);
      });
      $('command-label').textContent = tr('Search commands');
      palette.setAttribute('aria-label', tr('Search commands'));
      $('command-query').placeholder = tr('Search commands');
      $('command-hint').textContent = commandMatches.length ? tr('↑ ↓ Navigate · Enter Select · Esc Close') : tr('No matching commands');
      $('command-close').textContent = tr('Close') + ' · Esc';
      highlightCommand();
    }
    function render() {
      for (const id of ['quick-presets', 'quick-backends']) {
        $(id).dataset.liveUi = '';
        $(id).querySelectorAll('button').forEach(button => {
          if (button.dataset.preset) button.querySelector('strong').textContent = ctx.presetLabel(button.dataset.preset);
          button.title = tr('Left click: apply · Right click: details'); button.dataset.hint = button.title;
        });
      }
      $('command-open').title = tr('Search commands (Ctrl+K)');
      $('command-open').setAttribute('aria-label', tr('Search commands (Ctrl+K)'));
      $('command-open-label').textContent = tr('Search commands');
      if (lastAttempt && !lastAttempt.ok && ui.output.value) ui.outputStats.textContent = tr('Previous result');
      markerChanged(); renderProgress();
      if (presetDialog.open) renderPresets(); if (inspector.open) renderInspector(); if (palette.open) renderCommands();
    }
    window.addEventListener('beforeunload', () => { closed = true; clearInterval(clock); clearTimeout(markerTimer); });
    return {render, markerChanged, insertMarker, runBuild, openInspector};
  }
  const api = {attach, markerEdit, configChanges, serializeOptions, sameBuild};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GuiExperience = api;
})(globalThis);
