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
    preferencesButton: $('preferences-btn'), preferencesOverlay: $('preferences-overlay'),
    railPreferencesButton: $('rail-preferences-btn'),
    preferencesClose: $('preferences-close'), preferencesReset: $('preferences-reset'),
    preferencesStatus: $('preferences-status'), density: $('density-select'),
    editorFontSize: $('editor-font-size'), editorFontValue: $('editor-font-value'),
    motion: $('motion-select'), rememberSections: $('remember-sections'),
  };

  let api = null;
  let bootstrap = null;
  let state = null;
  let preferences = null;
  let preferenceSaveTimer = null;
  let preferenceRevision = 0;
  let originalFilename = 'obfuscated.lua';
  let inputPath = '';
  let executionId = null;
  let executionStarting = false;
  let executionTarget = '';
  let executionStatusParts = [];
  const systemDark = window.matchMedia('(prefers-color-scheme: dark)');

  const clone = (value) => JSON.parse(JSON.stringify(value));
  const titleCase = (value) => String(value || '').replace(/[-_]/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  const formatPercent = (value) => `${Math.round(Number(value || 0) * 100)}%`;
  const presetLabels = { dev: ['빠르게', '가벼운 보호'], 'fast-vm': ['균형', '기본 추천'], high: ['강하게', '높은 보호'], max: ['최대', '실험적'] };
  const preferenceTabs = ['appearance', 'gui', 'editor', 'general'];
  const editors = [window.LuaCodeEditor.attach(ui.input), window.LuaCodeEditor.attach(ui.output)];
  const tr = text => window.GuiI18n.tr(text, preferences?.language || 'ko');
  const refreshEditors = () => editors.forEach(editor => editor.refresh());
  let preferenceOpener = null;
  let settingsOpener = null;
  let editorView = 'source';

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
      preferences = bootstrap.preferences;
      renderThemes();
      applyPreferences();
      ensureConfigShape();
      renderPresetChoices();
      bindStaticEvents();
      renderAll();
      const version = await api.get_version();
      document.getElementById("app-version").textContent = `v${version}`;
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
    state.config.target ||= {};
    state.config.selection_modes ||= {};
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
      ui.preset.add(new Option(tr(presetLabels[name]?.[0] || titleCase(name)), name));
    });
    ui.preset.add(new Option('<Custom>', 'custom'));
    const container = $('quick-presets');
    container.replaceChildren();
    Object.keys(bootstrap.profiles).forEach(name => {
      const button = document.createElement('button');
      button.className = 'preset-button';
      button.dataset.preset = name;
      const config = bootstrap.profiles[name];
      button.title = `${name} · ${config.vm_options.vm_count} VM\n${config.passes.join(' → ')}\nVM: ${config.vm_output_passes.join(' → ')}`;
      const [label] = presetLabels[name] || [titleCase(name)];
      const title = document.createElement('strong'); title.textContent = label;
      button.append(title);
      button.addEventListener('click', () => applyPreset(name));
      container.appendChild(button);
    });
  }

  function applyPreset(name) {
    if (name === 'custom') {
      state.preset = 'custom';
      updateOverview();
      return;
    }
    const retained = { target: clone(state.config.target || {}) };
    ['selection_modes', 'selection_profiles', 'signature'].forEach(key => {
      if (state.config[key]) retained[key] = clone(state.config[key]);
    });
    ['lua_executable', 'luac_executable', 'lua_library'].forEach(key => {
      if (state.config[key]) retained[key] = state.config[key];
    });
    state.config = { ...clone(bootstrap.profiles[name]), ...retained };
    state.preset = name;
    state.protection_level = ({ dev: 'light', 'fast-vm': 'balanced', high: 'strong', max: 'maximum' })[name] || inferLevel();
    state.release_check = name === 'max';
    ensureConfigShape();
    renderAll();
  }

  function bindStaticEvents() {
    $('execute-source-btn').addEventListener('click', () => executeCode('source'));
    $('execute-output-btn').addEventListener('click', () => executeCode('output'));
    $('execution-stop').addEventListener('click', async () => {
      if (executionId) await api.stop_execution(executionId);
    });
    $('console-toggle').addEventListener('click', () => showConsole($('execution-console').hidden));
    $('console-hide').addEventListener('click', () => showConsole(false));
    $('console-clear').addEventListener('click', () => $('console-output').replaceChildren());
    $('console-input-form').addEventListener('submit', sendConsoleInput);
    document.addEventListener('keydown', event => {
      if (event.key !== 'F5' || event.ctrlKey || event.altKey || event.metaKey) return;
      event.preventDefault();
      if (!$('preferences-overlay').classList.contains('hidden')) return;
      executeCode(event.shiftKey ? 'output' : 'source');
    });
    ui.preset.addEventListener('change', () => applyPreset(ui.preset.value));
    $('marker-kind').addEventListener('change', () => {
      $('marker-options').value = '';
      renderMarkerHint();
    });
    $('marker-tools').addEventListener('toggle', renderMarkerHint);
    $('insert-marker-btn').addEventListener('click', insertMarker);
    preferenceTabs.forEach(name => {
      $(`${name}-tab`).addEventListener('click', () => selectPreferenceTab(name));
      $(`${name}-tab`).addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
        event.preventDefault();
        const index = preferenceTabs.indexOf(name);
        const next = event.key === 'Home' ? preferenceTabs[0] : event.key === 'End' ? preferenceTabs.at(-1)
          : preferenceTabs[(index + (event.key === 'ArrowRight' ? 1 : -1) + preferenceTabs.length) % preferenceTabs.length];
        selectPreferenceTab(next);
        $(`${next}-tab`).focus();
      });
    });
    document.querySelectorAll('[data-gui-choice]').forEach(button => {
      button.addEventListener('click', () => updatePreference('gui_version', button.dataset.guiChoice));
    });
    $('language-select').addEventListener('change', event => {
      updatePreference('language', event.target.value);
      renderAll();
    });
    $('settings-open').addEventListener('click', () => toggleSettings(true));
    $('settings-close').addEventListener('click', () => toggleSettings(false));
    $('settings-backdrop').addEventListener('click', () => toggleSettings(false));
    ['source', 'output'].forEach(view => {
      $(`${view}-view`).addEventListener('click', () => setEditorView(view));
      $(`${view}-view`).addEventListener('keydown', event => {
        if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
        event.preventDefault();
        const next = view === 'source' ? 'output' : 'source';
        setEditorView(next); $(`${next}-view`).focus();
      });
    });
    $('split-view').addEventListener('click', () => setEditorView(editorView === 'split' ? 'source' : 'split'));

    ui.level.addEventListener('change', () => {
      const name = ui.level.value;
      if (name === 'custom') {
        state.protection_level = 'custom';
        updateOverview();
        return;
      }
      const backend = state.config.vm_options.backend ?? 'karity';
      const requirements = clone(state.config.vm_options.requirements ?? {});
      state.config.vm_options = clone(bootstrap.protection_levels[name]);
      state.config.vm_options.backend = backend;
      state.config.vm_options.requirements = requirements;
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
    ui.preferencesButton.addEventListener('click', openPreferences);
    ui.railPreferencesButton.addEventListener('click', openPreferences);
    ui.preferencesClose.addEventListener('click', closePreferences);
    ui.preferencesOverlay.addEventListener('click', event => {
      if (event.target === ui.preferencesOverlay) closePreferences();
    });
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && !ui.preferencesOverlay.classList.contains('hidden')) closePreferences();
      if (event.key === 'Escape') $('marker-tools').open = false;
      if (event.key === 'Escape' && ui.preferencesOverlay.classList.contains('hidden')) toggleSettings(false);
      if (event.key === 'Tab' && !ui.preferencesOverlay.classList.contains('hidden')) {
        const controls = [...ui.preferencesOverlay.querySelectorAll('button, select, input')].filter(el => !el.disabled && el.tabIndex >= 0 && el.getClientRects().length);
        const first = controls[0], last = controls[controls.length - 1];
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
      }
    });
    ui.density.addEventListener('change', event => updatePreference('density', event.target.value));
    ui.editorFontSize.addEventListener('input', event => {
      preferences.editor_font_size = Number(event.target.value);
      ui.editorFontValue.textContent = event.target.value;
      applyPreferences();
      schedulePreferenceSave();
    });
    ui.motion.addEventListener('change', event => updatePreference('motion', event.target.value));
    ui.rememberSections.addEventListener('change', event => {
      preferences.remember_sections = event.target.checked;
      if (!event.target.checked) preferences.sections = {};
      bindSectionPreferences();
      schedulePreferenceSave();
    });
    ui.preferencesReset.addEventListener('click', () => {
      preferences = clone(bootstrap.preference_defaults);
      applyPreferences();
      document.querySelectorAll('details[data-section-key]').forEach(details => {
        details.open = ['pipeline', 'signature'].includes(details.dataset.sectionKey)
          || ['vm:Execution', 'vm:Semantic routing', 'vm:Runtime diversity'].includes(details.dataset.sectionKey);
      });
      renderAll();
      schedulePreferenceSave(true);
    });
    systemDark.addEventListener?.('change', () => {
      if (preferences.theme === 'system') applyPreferences();
    });

    ['lua_version', 'environment', 'compatibility'].forEach(key => {
      $(`target-${key}`).addEventListener('change', event => {
        state.config.target[key] = event.target.value;
        markPresetCustom(false);
      });
    });
    $('target-host_images').addEventListener('input', event => {
      state.config.target.host_images = event.target.value.split(/\r?\n/).map(path => path.trim()).filter(Boolean);
      markPresetCustom(false);
    });
    ['lua_executable', 'luac_executable', 'lua_library'].forEach(key => {
      $(key).addEventListener('input', event => {
        state.config[key] = event.target.value.trim() || null;
        markPresetCustom(false);
      });
    });

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
    $('target-host_images').value = (state.config.target.host_images || []).join('\n');
    Object.entries({lua_version: '5.3', environment: 'standalone', compatibility: 'runtime_specific'}).forEach(([key, fallback]) => {
      $(`target-${key}`).value = state.config.target[key] || fallback;
    });
    ['lua_executable', 'luac_executable', 'lua_library'].forEach(key => {
      $(key).value = state.config[key] || '';
    });
    ui.preset.value = bootstrap.profiles[state.preset] ? state.preset : 'custom';
    ui.level.value = bootstrap.protection_levels[state.protection_level] ? state.protection_level : 'custom';
    ui.releaseCheck.checked = Boolean(state.release_check);
    ui.source.textContent = bootstrap.profile_source ? `profiles: ${bootstrap.profile_source}` : 'profiles unavailable';
    renderPasses();
    renderVmOptions();
    renderSignature();
    renderMarkerHint();
    updateOverview();
    bindSectionPreferences();
    window.GuiI18n.localize(document.body, preferences.language);
    refreshEditors();
  }

  function resolvedTheme() {
    return preferences.theme === 'system' ? (systemDark.matches ? 'deepdark' : 'light') : preferences.theme;
  }

  function applyPreferences() {
    const root = document.documentElement;
    const previousVersion = root.dataset.guiVersion;
    root.dataset.theme = resolvedTheme();
    root.dataset.themePreference = preferences.theme;
    root.dataset.density = preferences.density;
    root.dataset.motion = preferences.motion;
    root.dataset.guiVersion = preferences.gui_version || 'v2';
    root.lang = preferences.language || 'ko';
    if (previousVersion !== root.dataset.guiVersion || !root.dataset.settingsOpen) toggleSettings(false);
    $('advanced-settings').open = true;
    const quick = document.querySelector('.quick-setup');
    const slot = root.dataset.guiVersion === 'v2' ? $('preset-toolbar-slot') : document.querySelector('.rail-scroll');
    if (quick.parentElement !== slot) slot.prepend(quick);
    applyTheme();
    setEditorView(editorView);
    document.querySelectorAll('[data-gui-choice]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.guiChoice === root.dataset.guiVersion));
    });
    document.querySelectorAll('[data-v2-placeholder]').forEach(element => {
      element.placeholder = tr(element.dataset.v2Placeholder);
    });
    if (ui.status.dataset.message) setStatus(ui.status.dataset.message, ui.status.dataset.type, ui.profileSummary.dataset.detail);
    root.style.setProperty('--editor-font-size', `${preferences.editor_font_size}px`);
    $('language-select').value = preferences.language;
    ui.density.value = preferences.density;
    ui.editorFontSize.value = preferences.editor_font_size;
    ui.editorFontValue.textContent = preferences.editor_font_size;
    ui.motion.value = preferences.motion;
    ui.rememberSections.checked = Boolean(preferences.remember_sections);
    ui.preferencesStatus.textContent = tr(ui.preferencesStatus.textContent);
    $('console-input').placeholder = tr('Type and press Enter');
    if (executionStatusParts.length) setExecutionStatus(...executionStatusParts);
    window.GuiI18n.localize(document.body, preferences.language);
    refreshEditors();
  }

  function updatePreference(name, value) {
    preferences[name] = value;
    applyPreferences();
    schedulePreferenceSave();
  }

  function openPreferences() {
    preferenceOpener = document.activeElement;
    applyPreferences();
    ui.preferencesOverlay.classList.remove('hidden');
    document.querySelector('.preference-tabs [aria-selected="true"]').focus();
  }

  function closePreferences() {
    ui.preferencesOverlay.classList.add('hidden');
    (preferenceOpener || ui.preferencesButton).focus();
  }

  function renderThemes() {
    $('theme-grid').replaceChildren();
    Object.entries(bootstrap.themes).forEach(([key, palette]) => {
      const button = document.createElement('button');
      button.className = 'theme-tile'; button.dataset.themeChoice = key;
      button.setAttribute('aria-label', palette.label);
      button.innerHTML = '<span class="theme-mini" aria-hidden="true"><i class="mini-dots"></i><i class="mini-sidebar"></i><i class="mini-code"><b></b><b></b><b></b><b></b></i></span><span class="theme-name"></span><span class="theme-check" aria-hidden="true">✓</span>';
      button.querySelector('.theme-name').textContent = palette.label;
      button.addEventListener('click', () => updatePreference('theme', key));
      $('theme-grid').appendChild(button);
    });
  }

  function applyTheme() {
    const palette = bootstrap.themes[resolvedTheme()];
    const root = document.documentElement;
    const mapping = {
      bg: 'background', panel: 'surface', 'panel-2': 'line', 'panel-3': 'raised',
      line: 'border', 'line-bright': 'muted', text: 'text', muted: 'muted', faint: 'comment',
      violet: 'accent', cyan: 'string', blue: 'keyword', danger: 'error', warning: 'number', success: 'string',
      'body-bg': 'background', 'shell-border': 'border', 'titlebar-bg': 'surface', 'rail-bg': 'surface',
      'footer-bg': 'surface', 'control-bg': 'raised', 'section-bg': 'surface', 'editor-bg': 'surface', 'output-bg': 'surface',
      'token-keyword': 'keyword', 'token-string': 'string', 'token-number': 'number', 'token-comment': 'comment',
      'token-function': 'accent', 'token-marker': 'accent', 'selection-bg': 'selection',
    };
    Object.entries(mapping).forEach(([variable, field]) => root.style.setProperty(`--${variable}`, palette[field]));
    root.style.setProperty('--workspace-gradient', palette.gradient || palette.background);
    root.style.colorScheme = ['light', 'crystal', 'mythic'].includes(resolvedTheme()) ? 'light' : 'dark';
    document.querySelectorAll('[data-theme-choice]').forEach(button => {
      const key = button.dataset.themeChoice;
      const preview = bootstrap.themes[key === 'system' ? resolvedThemeForSystem() : key];
      ['background', 'surface', 'raised', 'border', 'accent', 'keyword', 'string', 'number', 'gradient'].forEach(field => {
        button.style.setProperty(`--mini-${field}`, preview[field] || preview.background);
      });
      button.setAttribute('aria-pressed', String(key === preferences.theme));
      button.querySelector('.theme-name').textContent = key === 'system' ? tr('System') : bootstrap.themes[key].label;
    });
  }

  function resolvedThemeForSystem() { return systemDark.matches ? 'deepdark' : 'light'; }

  function toggleSettings(open) {
    const v2 = document.documentElement.dataset.guiVersion === 'v2';
    if (open) settingsOpener = document.activeElement;
    document.documentElement.dataset.settingsOpen = String(open && v2);
    document.querySelector('.settings-rail').inert = v2 && !open;
    $('settings-backdrop').classList.toggle('hidden', !open || !v2);
    $('settings-open').setAttribute('aria-expanded', String(open && v2));
    if (open && v2) $('settings-close').focus();
    else if (settingsOpener && ui.preferencesOverlay.classList.contains('hidden')) { settingsOpener.focus(); settingsOpener = null; }
  }

  function setEditorView(view) {
    editorView = view;
    document.documentElement.dataset.editorView = view;
    ['source', 'output'].forEach(name => {
      $(`${name}-view`).setAttribute('aria-selected', String(name === view || view === 'split' && name === 'source'));
      $(`${name}-view`).tabIndex = name === view || view === 'split' && name === 'source' ? 0 : -1;
    });
    $('split-view').setAttribute('aria-pressed', String(view === 'split'));
    refreshEditors();
  }

  function selectPreferenceTab(name) {
    preferenceTabs.forEach(tab => {
      const active = tab === name;
      $(`${tab}-tab`).setAttribute('aria-selected', String(active));
      $(`${tab}-tab`).tabIndex = active ? 0 : -1;
      $(`${tab}-tab`).classList.toggle('active', active);
      $(`${tab}-panel`).classList.toggle('hidden', !active);
    });
  }

  function schedulePreferenceSave(immediate = false) {
    clearTimeout(preferenceSaveTimer);
    preferenceRevision += 1;
    ui.preferencesStatus.textContent = tr('Saving…');
    const revision = preferenceRevision;
    preferenceSaveTimer = setTimeout(() => savePreferences(revision), immediate ? 0 : 350);
  }

  async function savePreferences(revision) {
    const snapshot = clone(preferences);
    try {
      const result = await api.save_preferences(snapshot);
      if (!result.ok) throw new Error('Save failed');
      if (revision === preferenceRevision) {
        preferences = result.preferences;
        ui.preferencesStatus.textContent = tr('Saved automatically');
      }
    } catch (error) {
      if (revision === preferenceRevision) ui.preferencesStatus.textContent = `Save failed: ${String(error)}`;
    }
  }

  function bindSectionPreferences() {
    document.querySelectorAll('details[data-section-key]').forEach(details => {
      const key = details.dataset.sectionKey;
      if (preferences.remember_sections && Object.prototype.hasOwnProperty.call(preferences.sections, key)) {
        details.open = preferences.sections[key];
      }
      if (details.dataset.preferenceBound) return;
      details.dataset.preferenceBound = 'true';
      details.addEventListener('toggle', () => {
        if (!preferences.remember_sections) return;
        preferences.sections[key] = details.open;
        schedulePreferenceSave();
      });
    });
  }

  function stripCommentTokens(value) {
    return String(value || '').replace(/--(?:\[(=*)\[)?|\](=*)\]/g, '').trimStart();
  }

  function renderMarkerHint() {
    const kind = $('marker-kind').value;
    const hasOptions = ['VM', 'VM_START', 'FUNCTION_OBF', 'FUNCTION_OBF_START'].includes(kind);
    $('marker-options').hidden = !hasOptions;
    $('marker-options-label').hidden = !hasOptions;
    $('marker-options').placeholder = kind.startsWith('FUNCTION') ? 'cff, junk=false' : 'profile="fast-vm", junk_rate=0.05';
    const hints = {
      STRING_OBF: '문자열 리터럴 선택 → 삽입', NUMBER_OBF: '숫자 리터럴 선택 → 삽입',
      BOOLEAN_OBF: 'true / false 선택 → 삽입', TABLE_OBF: '테이블 { … } 선택 → 삽입',
      VM_START: '완전한 문장들을 선택 → VM 영역', FUNCTION_OBF: '함수 앞에 삽입',
      FUNCTION_OBF_START: '함수 내부 문장들을 선택 → 보호 영역', VM: '파일 맨 앞에 삽입',
      NO_VM: '함수 앞에 삽입 → VM 제외', NO_VM_START: '문장들을 선택 → VM 제외',
      NO_OBF_START: '문장들을 선택 → 보호 제외',
    };
    $('marker-hint').textContent = tr(hints[kind]);
  }

  function insertMarker() {
    const editor = ui.input;
    const kind = $('marker-kind').value;
    let start = editor.selectionStart, end = editor.selectionEnd;
    const source = editor.value;
    const selected = source.slice(start, end);
    const macro = ['STRING_OBF', 'NUMBER_OBF', 'BOOLEAN_OBF', 'TABLE_OBF'].includes(kind);
    if ((macro || kind.endsWith('_START')) && !selected.trim()) {
      $('marker-hint').textContent = tr('코드에서 보호할 부분을 먼저 선택하세요.');
      editor.focus();
      return;
    }
    const hasOptions = ['VM', 'VM_START', 'FUNCTION_OBF', 'FUNCTION_OBF_START'].includes(kind);
    let options = hasOptions ? $('marker-options').value.trim() : '';
    if (/[\r\n]/.test(options)) {
      $('marker-hint').textContent = tr('옵션은 한 줄로 입력하세요.');
      return;
    }
    if (options.startsWith('(') && options.endsWith(')')) options = options.slice(1, -1);
    const suffix = options ? `(${options})` : '';
    let replacement;
    if (macro) replacement = `${kind}(${selected})`;
    else {
      if (kind === 'VM') { start = 0; end = 0; }
      else {
        start = start > 0 ? source.lastIndexOf('\n', start - 1) + 1 : 0;
        if (kind.endsWith('_START')) {
          // Keep complete physical lines; a selection ending at a line start
          // must not consume the next statement.
          const next = source.indexOf('\n', end - (source[end - 1] === '\n' ? 1 : 0));
          end = next < 0 ? source.length : next + 1;
        } else end = start;
      }
      const indent = source.slice(start).match(/^[\t ]*/)[0];
      replacement = `${indent}-- @${kind}${suffix}\n`;
      if (kind.endsWith('_START')) {
        const body = source.slice(start, end);
        replacement += body + (body.endsWith('\n') ? '' : '\n');
        replacement += `${indent}-- @${kind.replace(/_START$/, '_END')}\n`;
      }
    }
    editor.focus();
    editor.setSelectionRange(start, end);
    editor.setRangeText(replacement, start, end, 'select');
    editor.dispatchEvent(new Event('input', { bubbles: true }));
    $('marker-tools').open = false;
    setStatus('마커 삽입됨', 'success', kind);
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
      details.dataset.sectionKey = `vm:${groupName}`;
      if (['Execution', 'Semantic routing', 'Runtime diversity'].includes(groupName)) details.open = true;
      details.innerHTML = `<summary><span>${groupName}</span><span class="section-count">${options.length}</span></summary><div class="section-body"></div>`;
      const body = details.querySelector('.section-body');
      options.forEach(option => body.appendChild(makeOptionRow(option)));
      ui.optionGroups.appendChild(details);
    });
    bindSectionPreferences();
  }

  function makeOptionRow(option) {
    const row = document.createElement('div');
    row.className = 'option-row';
    row.dataset.hint = option.description;
    row.innerHTML = `<div><span class="option-label">${option.label}</span><small class="option-description">${option.name}</small></div><div class="option-control"></div>`;
    const host = row.querySelector('.option-control');
    const current = state.config.vm_options[option.name] ?? option.default;

    if (option.kind === 'requirements') {
      const fields = document.createElement('div');
      option.features.forEach(feature => {
        const label = document.createElement('label');
        label.textContent = feature.replaceAll('_', ' ') + ' ';
        const select = document.createElement('select');
        select.className = 'select-control';
        select.add(new Option('Optional', 'optional'));
        select.add(new Option('Required', 'required'));
        select.value = current[feature] ?? 'optional';
        select.addEventListener('change', () => {
          const requirements = {...current};
          if (select.value === 'optional') delete requirements[feature];
          else requirements[feature] = select.value;
          setVmOption(option.name, requirements);
        });
        label.appendChild(select);
        fields.appendChild(label);
      });
      host.appendChild(fields);
    } else if (option.kind === 'boolean') {
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
    const selected = state.config.vm_options.backend ?? 'karity';
    const backend = bootstrap.backend_aliases[selected] ?? selected;
    if (option.resolution[backend]?.outcome === 'fallback') {
      row.querySelector('.option-description').textContent = `Fallback: ${option.resolution[backend].target}`;
    }
    if (option.resolution[backend]?.outcome === 'disable') {
      row.classList.add('unsupported-option');
      row.querySelectorAll('input, select').forEach(control => { control.disabled = true; });
      row.querySelector('.option-description').textContent = `Not used by ${backend}; saved value retained`;
      row.dataset.hint = `This option does not apply to ${backend}. Switch backends to edit it.`;
    }
    return row;
  }

  function setVmOption(name, value, rerender = true) {
    state.config.vm_options[name] = value;
    markPresetCustom(name !== 'backend');
    if (rerender) renderAll();
    else updateOverview();
  }

  function markPresetCustom(vmChanged) {
    state.preset = 'custom';
    if (vmChanged) state.protection_level = 'custom';
    ui.preset.value = 'custom';
    if (vmChanged) ui.level.value = 'custom';
    updateOverview();
  }

  function inferLevel() {
    const comparable = options => {
      const result = clone(options);
      delete result.backend;
      return JSON.stringify(result);
    };
    const options = comparable(state.config.vm_options);
    return Object.keys(bootstrap.protection_levels).find(name => comparable(bootstrap.protection_levels[name]) === options) || 'custom';
  }

  function updateOverview() {
    document.querySelectorAll('[data-preset]').forEach(button => {
      button.setAttribute('aria-pressed', String(button.dataset.preset === state.preset));
    });
    $('quick-preset-status').textContent = state.preset === 'custom' ? tr('커스텀 설정') : '';
    const allPasses = [...state.config.passes, ...state.config.vm_output_passes, ...state.config.packer_output_passes];
    ui.pipelineCount.textContent = allPasses.length;
    ui.activePreset.textContent = titleCase(state.preset);
    ui.activeLevel.textContent = titleCase(state.protection_level);
    ui.metricPasses.textContent = allPasses.length;
    ui.metricVms.textContent = state.config.vm_options.vm_count ?? 1;
    ui.metricRuntime.textContent = !bootstrap.vm_options.find(option => option.name === 'runtime_polymorphism_rate').supported_backends.includes(bootstrap.backend_aliases[state.config.vm_options.backend] ?? state.config.vm_options.backend)
      ? 'N/A' : formatPercent(state.config.vm_options.runtime_polymorphism_rate);
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
      ui.saveStatus.textContent = tr(result.ok ? 'Saved locally' : 'Save failed');
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
    refreshEditors();
    ui.inputFilename.textContent = result.name;
    originalFilename = result.name;
    inputPath = result.path || '';
    setStatus('Source loaded', 'success', `${result.name} · ${result.content.length.toLocaleString()} characters`);
  }

  function clearInput() {
    inputPath = '';
    ui.input.value = ''; ui.inputFilename.textContent = ''; originalFilename = 'obfuscated.lua';
    refreshEditors();
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
        refreshEditors();
        if (editorView !== 'split') setEditorView('output');
        ui.outputStats.textContent = 'error';
        setStatus('Build failed', 'error', lastErrorLine(result.error));
        return;
      }
      ui.output.value = result.output;
      refreshEditors();
      $('result-dot').classList.add('has-result');
      if (editorView !== 'split') setEditorView('output');
      ui.outputStats.textContent = `${result.output.length.toLocaleString()} chars · ${result.elapsed}s`;
      const passCount = result.profile?.passes?.length || 0;
      if (result.warnings?.length) {
        setStatus('Protection complete (options ignored)', 'success', result.warnings.join('\n'));
        return;
      }
      setStatus('Protection complete', 'success', `${passCount} passes · ${result.elapsed}s total`);
    } catch (error) {
      setStatus('Build failed', 'error', String(error));
    } finally {
      ui.run.disabled = false;
    }
  }

  function showConsole(visible) {
    $('execution-console').hidden = !visible;
    $('console-toggle').setAttribute('aria-expanded', String(visible));
    requestAnimationFrame(refreshEditors);
  }

  function appendConsole(text, stream = 'stdout') {
    const output = $('console-output');
    const follow = output.scrollHeight - output.scrollTop - output.clientHeight < 30;
    const span = document.createElement('span');
    span.className = `console-${stream}`;
    span.textContent = text;
    output.appendChild(span);
    while (output.textContent.length > 300000 && output.firstChild) {
      const excess = output.textContent.length - 300000;
      if (output.firstChild.textContent.length <= excess) output.firstChild.remove();
      else output.firstChild.textContent = output.firstChild.textContent.slice(excess);
    }
    // Bound DOM nodes as well as character count during tiny repeated writes.
    while (output.childNodes.length > 1200) output.firstChild.remove();
    if (follow) output.scrollTop = output.scrollHeight;
  }

  function executionControls(running) {
    ['execute-source-btn', 'execute-output-btn'].forEach(id => $(id).disabled = running);
    ['execution-stop', 'console-input', 'console-send'].forEach(id => $(id).disabled = !running);
    $('console-toggle').classList.toggle('is-running', running);
  }

  function setExecutionStatus(...parts) {
    executionStatusParts = parts;
    $('execution-status').textContent = parts.map(part => tr(String(part))).join(' · ');
  }

  async function executeCode(target) {
    if (executionId || executionStarting) return;
    showConsole(true);
    $('console-output').replaceChildren();
    $('console-input').value = '';
    executionStarting = true;
    executionTarget = target === 'source' ? 'Source' : 'Output';
    setExecutionStatus(executionTarget, 'Starting…');
    executionControls(true);
    ['execution-stop', 'console-input', 'console-send'].forEach(id => $(id).disabled = true);
    try {
      const result = await api.start_execution({
        script: target === 'source' ? ui.input.value : ui.output.value,
        config: clone(state.config), target, source_path: inputPath,
      });
      if (!result.ok) throw new Error(result.error);
      executionId = result.id;
      executionControls(true);
      setExecutionStatus(executionTarget, `Lua ${result.lua_version}`, 'Running');
      pollExecution(result.id, 0);
    } catch (error) {
      appendConsole(`${tr(error.message || String(error))}\n`, 'stderr');
      setExecutionStatus('Run failed');
      executionControls(false);
    } finally {
      executionStarting = false;
    }
  }

  async function pollExecution(id, cursor) {
    if (executionId !== id) return;
    try {
      const result = await api.poll_execution(id, cursor);
      if (!result.ok) throw new Error(result.error);
      if (result.truncated) appendConsole(`${tr('Earlier output omitted')}\n`, 'meta');
      result.events.forEach(event => appendConsole(event.text, event.stream));
      if (result.done) {
        const outcome = result.stopped ? 'Stopped' : result.exit_code === 0 ? 'Finished' : 'Run failed';
        setExecutionStatus(executionTarget, outcome, result.exit_code, `${result.elapsed}s`);
        executionId = null;
        executionControls(false);
        return;
      }
      setTimeout(() => pollExecution(id, result.cursor), 90);
    } catch (error) {
      appendConsole(`${error.message || error}\n`, 'stderr');
      setExecutionStatus('Run failed');
      // Keep the run token and stop button available if the bridge lost a poll.
      setTimeout(() => pollExecution(id, cursor), 1000);
    }
  }

  async function sendConsoleInput(event) {
    event.preventDefault();
    if (!executionId) return;
    const input = $('console-input');
    const value = input.value;
    const result = await api.send_execution_input(executionId, value);
    if (result.ok) {
      appendConsole(`› ${value}\n`, 'meta');
      input.value = '';
    } else appendConsole(`${tr(result.error)}\n`, 'stderr');
  }

  function lastErrorLine(text) {
    const lines = String(text || '').trim().split(/\r?\n/);
    return [...lines].reverse().find(line => /^[\w.]*(?:Error|Exception):/.test(line)) || lines.at(-1) || 'Unknown error';
  }

  function setStatus(message, type, detail) {
    ui.status.dataset.message = message;
    ui.status.dataset.type = type || 'idle';
    ui.profileSummary.dataset.detail = detail || '';
    const compact = document.documentElement.dataset.guiVersion === 'v2';
    ui.status.textContent = tr(message);
    ui.profileSummary.textContent = compact && message === 'Ready' ? '' : tr(detail || '');
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
