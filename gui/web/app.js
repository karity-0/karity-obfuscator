document.addEventListener('DOMContentLoaded', () => {
  const $ = (id) => document.getElementById(id);
  const ui = {
    preset: $('preset-select'), level: $('level-select'), source: $('config-source'),
    passLists: { passes: $('passes-list'), vm_output_passes: $('vm-output-list'), packer_output_passes: $('packer-output-list') },
    optionGroups: $('vm-option-groups'), pipelineCount: $('pipeline-count'),
    activePreset: $('active-preset'), activeLevel: $('active-level'),
    metricPasses: $('metric-passes'), metricVms: $('metric-vms'), metricRuntime: $('metric-runtime'),
    pipeline: $('pipeline-strip'), pipelineHint: $('pipeline-hint'),
    input: $('input-script'), output: $('output-script'), inputFilename: $('input-filename'),
    outputStats: $('output-stats'), status: $('status-msg'), statusIndicator: $('status-indicator'),
    profileSummary: $('profile-summary'), releaseCheck: $('release-check'),
    backendLabel: $('backend-label'), tooltip: $('tooltip'), saveStatus: $('config-status'),
    run: $('run-btn'), open: $('open-file-btn'), clear: $('clear-input-btn'),
    copy: $('copy-output-btn'), saveOutput: $('save-output-btn'), saveConfig: $('save-config-btn'),
    signatureModeLabel: $('signature-mode-label'), signatureFake: $('signature-fake-options'),
    signatureGeneratorOptions: $('signature-generator-options'), signatureCustomOptions: $('signature-custom-options'),
    signatureWellKnown: $('signature-well-known'), signatureGenerator: $('signature-generator'),
    signatureCustomPattern: $('signature-custom-pattern'), signatureCustom: $('signature-custom'),
  };

  let api = null;
  let bootstrap = null;
  let state = null;
  let originalFilename = 'obfuscated.lua';

  const clone = (value) => JSON.parse(JSON.stringify(value));
  const titleCase = (value) => String(value || '').replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const formatPercent = (value) => `${Math.round(Number(value || 0) * 100)}%`;

  $('win-min').addEventListener('click', () => window.pywebview?.api?.window_minimize());
  $('win-max').addEventListener('click', () => window.pywebview?.api?.window_toggle_maximize());
  $('win-close').addEventListener('click', () => window.pywebview?.api?.window_close());

  if (window.pywebview?.api) initialize();
  else window.addEventListener('pywebviewready', initialize);

  async function initialize() {
    api = window.pywebview.api;
    try {
      bootstrap = await api.get_bootstrap();
      state = bootstrap.state;
      ensureConfigShape();
      renderPresetChoices();
      bindStaticEvents();
      renderAll();
      ui.backendLabel.textContent = 'backend ready';
      document.querySelector('.live-dot')?.classList.add('ready');
      setStatus('Ready', 'idle', 'Choose a preset or tune individual controls.');
    } catch (error) {
      setStatus('Initialization failed', 'error', String(error));
    }
  }

  function ensureConfigShape() {
    state.config ||= {};
    state.config.passes ||= [];
    state.config.vm_output_passes ||= [];
    state.config.packer_output_passes ||= [];
    state.config.vm_options ||= {};
    state.config.signature ||= {
      mode: 'default',
      fake: { sources: ['well_known', 'generated'], generator_patterns: [
        'Obfuscated using {name} obfuscator!', 'Protected with {name} V{version}',
        '{name} Lua Protection\nBuild V{version}', 'Secured by {name}\nVersion: {version}'
      ], custom_pattern: '' },
      custom: ''
    };
    state.config.signature.fake ||= { sources: ['well_known', 'generated'], generator_patterns: [] };
    state.config.signature.fake.sources ||= [];
    state.config.signature.fake.generator_patterns ||= [];
    state.preset ||= 'custom';
    state.protection_level ||= 'custom';
  }

  function renderPresetChoices() {
    ui.preset.innerHTML = '';
    Object.keys(bootstrap.profiles).forEach(name => {
      ui.preset.add(new Option(titleCase(name), name));
    });
    ui.preset.add(new Option('<Custom>', 'custom'));
  }

  function bindStaticEvents() {
    ui.preset.addEventListener('change', () => {
      const name = ui.preset.value;
      if (name === 'custom') {
        state.preset = 'custom';
        updateOverview();
        return;
      }
      state.config = clone(bootstrap.profiles[name]);
      state.preset = name;
      state.protection_level = ({ dev: 'light', 'fast-vm': 'balanced', max: 'maximum' })[name] || inferLevel();
      state.release_check = name === 'max';
      ensureConfigShape();
      renderAll();
    });

    ui.level.addEventListener('change', () => {
      const name = ui.level.value;
      if (name === 'custom') {
        state.protection_level = 'custom';
        updateOverview();
        return;
      }
      state.config.vm_options = clone(bootstrap.protection_levels[name]);
      state.protection_level = name;
      state.preset = 'custom';
      renderAll();
    });

    ui.releaseCheck.addEventListener('change', () => {
      state.release_check = ui.releaseCheck.checked;
    });

    ui.saveConfig.addEventListener('click', saveConfiguration);
    ui.open.addEventListener('click', openFile);
    ui.clear.addEventListener('click', clearInput);
    ui.copy.addEventListener('click', copyOutput);
    ui.saveOutput.addEventListener('click', saveOutput);
    ui.run.addEventListener('click', runObfuscation);

    document.querySelectorAll('input[name="signature-mode"]').forEach(input => {
      input.addEventListener('change', event => {
        state.config.signature.mode = event.target.value;
        markPresetCustom(false);
        renderSignature();
      });
    });
    ui.signatureWellKnown.addEventListener('change', event => setSignatureSource('well_known', event.target.checked));
    ui.signatureGenerator.addEventListener('change', event => setSignatureSource('generated', event.target.checked));
    document.querySelectorAll('.signature-pattern').forEach(input => {
      input.addEventListener('change', event => setGeneratorPattern(event.target.value, event.target.checked));
    });
    ui.signatureCustomPattern.addEventListener('input', event => {
      event.target.value = stripCommentTokens(event.target.value);
      state.config.signature.fake.custom_pattern = event.target.value;
      markPresetCustom(false);
    });
    ui.signatureCustom.addEventListener('input', event => {
      event.target.value = stripCommentTokens(event.target.value);
      state.config.signature.custom = event.target.value;
      markPresetCustom(false);
    });

    document.addEventListener('mouseover', showTooltip);
    document.addEventListener('mousemove', moveTooltip);
    document.addEventListener('mouseout', hideTooltip);
  }

  function renderAll() {
    ensureConfigShape();
    ui.preset.value = bootstrap.profiles[state.preset] ? state.preset : 'custom';
    ui.level.value = bootstrap.protection_levels[state.protection_level] ? state.protection_level : 'custom';
    ui.releaseCheck.checked = Boolean(state.release_check);
    ui.source.textContent = bootstrap.profile_source ? `profiles: ${bootstrap.profile_source}` : 'profiles unavailable';
    renderPasses();
    renderVmOptions();
    renderSignature();
    updateOverview();
  }

  function stripCommentTokens(value) {
    return String(value || '').replace(/--(?:\[(=*)\[)?|\](=*)\]/g, '').trimStart();
  }

  function renderSignature() {
    const signature = state.config.signature;
    const displayMode = signature.mode === 'generated' ? 'fake' : signature.mode;
    document.querySelectorAll('input[name="signature-mode"]').forEach(input => {
      input.checked = input.value === displayMode;
    });
    const sources = signature.mode === 'generated' ? ['generated'] : signature.fake.sources;
    ui.signatureWellKnown.checked = sources.includes('well_known');
    ui.signatureGenerator.checked = sources.includes('generated');
    ui.signatureFake.classList.toggle('hidden', displayMode !== 'fake');
    ui.signatureGeneratorOptions.classList.toggle('hidden', displayMode !== 'fake' || !ui.signatureGenerator.checked);
    ui.signatureCustomOptions.classList.toggle('hidden', displayMode !== 'custom');
    document.querySelectorAll('.signature-pattern').forEach(input => {
      input.checked = signature.fake.generator_patterns.includes(input.value);
    });
    ui.signatureCustomPattern.value = signature.fake.custom_pattern || signature.custom_pattern || '';
    ui.signatureCustom.value = signature.custom || '';
    ui.signatureModeLabel.textContent = signature.mode;
  }

  function setSignatureSource(source, enabled) {
    if (state.config.signature.mode === 'generated') state.config.signature.mode = 'fake';
    const sources = state.config.signature.fake.sources;
    const index = sources.indexOf(source);
    if (enabled && index < 0) sources.push(source);
    if (!enabled && index >= 0) sources.splice(index, 1);
    if (!sources.length) {
      sources.push(source === 'well_known' ? 'generated' : 'well_known');
    }
    markPresetCustom(false);
    renderSignature();
  }

  function setGeneratorPattern(pattern, enabled) {
    const patterns = state.config.signature.fake.generator_patterns;
    const index = patterns.indexOf(pattern);
    if (enabled && index < 0) patterns.push(pattern);
    if (!enabled && index >= 0) patterns.splice(index, 1);
    markPresetCustom(false);
  }

  function renderPasses() {
    Object.entries(ui.passLists).forEach(([context, container]) => {
      container.innerHTML = '';
      bootstrap.passes.filter(pass => pass.contexts.includes(context)).forEach(pass => {
        const enabled = state.config[context].includes(pass.name);
        const label = document.createElement('label');
        label.className = `toggle-item${enabled ? ' enabled' : ''}`;
        label.dataset.hint = pass.description;
        label.innerHTML = `<input type="checkbox" ${enabled ? 'checked' : ''}><span class="toggle-dot"></span><span class="toggle-name">${pass.label}</span>`;
        label.querySelector('input').addEventListener('change', event => {
          togglePass(context, pass.name, event.target.checked);
          markPresetCustom(false);
          renderPasses();
          updateOverview();
        });
        container.appendChild(label);
      });
    });
  }

  function togglePass(context, name, enabled) {
    const values = state.config[context];
    const index = values.indexOf(name);
    if (enabled && index < 0) values.push(name);
    if (!enabled && index >= 0) values.splice(index, 1);
  }

  function renderVmOptions() {
    ui.optionGroups.innerHTML = '';
    const groups = new Map();
    bootstrap.vm_options.forEach(option => {
      if (!groups.has(option.group)) groups.set(option.group, []);
      groups.get(option.group).push(option);
    });
    groups.forEach((options, groupName) => {
      const details = document.createElement('details');
      details.className = 'config-section';
      if (['Execution', 'Semantic routing', 'Runtime diversity'].includes(groupName)) details.open = true;
      details.innerHTML = `<summary><span>${groupName}</span><span class="section-count">${options.length}</span></summary><div class="section-body"></div>`;
      const body = details.querySelector('.section-body');
      options.forEach(option => body.appendChild(makeOptionRow(option)));
      ui.optionGroups.appendChild(details);
    });
  }

  function makeOptionRow(option) {
    const row = document.createElement('div');
    row.className = 'option-row';
    row.dataset.hint = option.description;
    row.innerHTML = `<div><span class="option-label">${option.label}</span><small class="option-description">${option.name}</small></div><div class="option-control"></div>`;
    const host = row.querySelector('.option-control');
    const current = state.config.vm_options[option.name] ?? option.default;

    if (option.kind === 'boolean') {
      const label = document.createElement('label');
      label.className = 'switch';
      label.innerHTML = `<input type="checkbox" ${current ? 'checked' : ''}><span class="switch-track"></span>`;
      label.querySelector('input').addEventListener('change', event => setVmOption(option.name, event.target.checked));
      host.appendChild(label);
    } else if (option.kind === 'select') {
      const select = document.createElement('select');
      select.className = 'select-control';
      option.values.forEach(item => select.add(new Option(item.label, item.value)));
      if (![...select.options].some(item => item.value === String(current))) select.add(new Option(String(current), String(current)));
      select.value = String(current);
      select.addEventListener('change', event => setVmOption(option.name, event.target.value));
      host.appendChild(select);
    } else if (option.kind === 'integer') {
      const input = document.createElement('input');
      input.type = 'number'; input.className = 'number-control';
      input.min = option.min; input.max = option.max; input.step = option.step; input.value = current;
      input.addEventListener('change', event => {
        const value = Math.max(Number(option.min), Math.min(Number(option.max), Number(event.target.value)));
        event.target.value = value;
        setVmOption(option.name, Math.trunc(value));
      });
      host.appendChild(input);
    } else {
      const wrap = document.createElement('div');
      wrap.className = 'range-wrap';
      wrap.innerHTML = `<input class="range-control" type="range" min="${option.min}" max="${option.max}" step="${option.step}" value="${current}"><span class="range-value">${Number(current).toFixed(2)}</span>`;
      const range = wrap.querySelector('input');
      const value = wrap.querySelector('.range-value');
      range.addEventListener('input', event => {
        value.textContent = Number(event.target.value).toFixed(2);
        setVmOption(option.name, Number(event.target.value), false);
      });
      range.addEventListener('change', () => renderAll());
      host.appendChild(wrap);
    }
    return row;
  }

  function setVmOption(name, value, rerender = true) {
    state.config.vm_options[name] = value;
    markPresetCustom(true);
    if (rerender) renderAll();
    else updateOverview();
  }

  function markPresetCustom(vmChanged) {
    state.preset = 'custom';
    if (vmChanged) state.protection_level = 'custom';
    ui.preset.value = 'custom';
    if (vmChanged) ui.level.value = 'custom';
  }

  function inferLevel() {
    const options = JSON.stringify(state.config.vm_options);
    return Object.keys(bootstrap.protection_levels).find(name => JSON.stringify(bootstrap.protection_levels[name]) === options) || 'custom';
  }

  function updateOverview() {
    const allPasses = [...state.config.passes, ...state.config.vm_output_passes, ...state.config.packer_output_passes];
    ui.pipelineCount.textContent = allPasses.length;
    ui.activePreset.textContent = titleCase(state.preset);
    ui.activeLevel.textContent = titleCase(state.protection_level);
    ui.metricPasses.textContent = allPasses.length;
    ui.metricVms.textContent = state.config.vm_options.vm_count ?? 1;
    ui.metricRuntime.textContent = formatPercent(state.config.vm_options.runtime_polymorphism_rate);
    renderPipeline();
  }

  function renderPipeline() {
    const names = state.config.passes;
    ui.pipeline.innerHTML = '';
    if (!names.length) {
      ui.pipeline.innerHTML = '<span class="pipeline-empty">No passes selected</span>';
      ui.pipelineHint.textContent = 'Select at least one main pass';
      return;
    }
    names.forEach((name, index) => {
      const meta = bootstrap.passes.find(pass => pass.name === name);
      const node = document.createElement('span');
      node.className = `pipeline-node${name === 'vm' ? ' vm' : ''}${name === 'pack' ? ' pack' : ''}`;
      node.textContent = meta?.label || name;
      ui.pipeline.appendChild(node);
      if (index < names.length - 1) {
        const arrow = document.createElement('span'); arrow.className = 'pipeline-arrow'; arrow.textContent = '→';
        ui.pipeline.appendChild(arrow);
      }
    });
    ui.pipelineHint.textContent = `${names.length} main stages · ${state.config.vm_output_passes.length} VM output · ${state.config.packer_output_passes.length} packer output`;
  }

  async function saveConfiguration() {
    try {
      const result = await api.save_config(state);
      ui.saveStatus.textContent = result.ok ? 'Saved locally' : 'Save failed';
    } catch (error) {
      ui.saveStatus.textContent = String(error);
    }
    setTimeout(() => { ui.saveStatus.textContent = ''; }, 2500);
  }

  async function openFile() {
    setStatus('Opening file…', 'running', 'Waiting for file selection.');
    const result = await api.pick_input_file();
    if (!result) return setStatus('Ready', 'idle', 'File selection cancelled.');
    if (result.error) return setStatus('Open failed', 'error', result.error);
    ui.input.value = result.content;
    ui.inputFilename.textContent = result.name;
    originalFilename = result.name;
    setStatus('Source loaded', 'success', `${result.name} · ${result.content.length.toLocaleString()} characters`);
  }

  function clearInput() {
    ui.input.value = ''; ui.inputFilename.textContent = ''; originalFilename = 'obfuscated.lua';
    setStatus('Ready', 'idle', 'Input cleared.');
  }

  async function copyOutput() {
    if (!ui.output.value) return;
    try {
      await navigator.clipboard.writeText(ui.output.value);
      setStatus('Copied', 'success', 'Protected output copied to clipboard.');
    } catch (error) {
      setStatus('Copy failed', 'error', String(error));
    }
  }

  async function saveOutput() {
    if (!ui.output.value) return setStatus('Nothing to save', 'error', 'Run protection first.');
    const base = originalFilename.replace(/\.lua$/i, '');
    const result = await api.save_output(ui.output.value, `${base}.protected.lua`);
    setStatus(result.ok ? 'Output saved' : 'Save cancelled', result.ok ? 'success' : 'idle', result.path || result.error || '');
  }

  async function runObfuscation() {
    if (!ui.input.value.trim()) return setStatus('Input required', 'error', 'Paste Lua source or open a file.');
    ui.run.disabled = true;
    setStatus('Protecting…', 'running', `${titleCase(state.preset)} / ${titleCase(state.protection_level)}`);
    try {
      const result = await api.run_obfuscation({
        script: ui.input.value,
        config: state.config,
        release_check: Boolean(state.release_check),
      });
      if (!result.ok) {
        ui.output.value = result.error;
        ui.outputStats.textContent = 'error';
        setStatus('Build failed', 'error', lastErrorLine(result.error));
        return;
      }
      ui.output.value = result.output;
      ui.outputStats.textContent = `${result.output.length.toLocaleString()} chars · ${result.elapsed}s`;
      const passCount = result.profile?.passes?.length || 0;
      setStatus('Protection complete', 'success', `${passCount} passes · ${result.elapsed}s total`);
    } catch (error) {
      setStatus('Build failed', 'error', String(error));
    } finally {
      ui.run.disabled = false;
    }
  }

  function lastErrorLine(text) {
    return String(text || '').trim().split(/\r?\n/).slice(-1)[0] || 'Unknown error';
  }

  function setStatus(message, type, detail) {
    ui.status.textContent = message;
    ui.profileSummary.textContent = detail || '';
    ui.statusIndicator.className = `status-indicator${type && type !== 'idle' ? ` ${type}` : ''}`;
  }

  function showTooltip(event) {
    const target = event.target.closest('[data-hint]');
    if (!target || !target.dataset.hint) return;
    ui.tooltip.textContent = target.dataset.hint;
    ui.tooltip.classList.add('active');
  }
  function moveTooltip(event) {
    if (!ui.tooltip.classList.contains('active')) return;
    ui.tooltip.style.left = `${Math.min(event.clientX + 14, window.innerWidth - 290)}px`;
    ui.tooltip.style.top = `${Math.min(event.clientY + 14, window.innerHeight - 90)}px`;
  }
  function hideTooltip(event) {
    if (event.target.closest('[data-hint]')) ui.tooltip.classList.remove('active');
  }
});
