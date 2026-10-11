/* Preset/backend transitions are pure so persistence and UI use one contract. */
(function (root) {
  const clone = value => JSON.parse(JSON.stringify(value));
  const contextKeys = ['target', 'signature', 'selection_modes', 'selection_profiles',
    '_selection_profiles', 'lua_executable', 'luac_executable', 'lua_library', 'debug_dumps'];
  function applyPreset(state, name, definition, revision) {
    const next = clone(state);
    next.preset_snapshots ||= {};
    if (state.preset && state.preset !== 'custom') {
      next.preset_snapshots[state.preset] = {
        config: clone(state.config), custom: Boolean(state.preset_custom),
        revision: state.preset_revision ?? null,
      };
    }
    const saved = next.preset_snapshots[name];
    next.config = clone(saved?.config || definition);
    for (const key of contextKeys) {
      if (Object.hasOwn(state.config, key)) next.config[key] = clone(state.config[key]);
    }
    next.config.vm_options ||= {};
    for (const key of ['backend', 'requirements']) {
      if (Object.hasOwn(state.config.vm_options || {}, key)) {
        next.config.vm_options[key] = clone(state.config.vm_options[key]);
      }
    }
    next.preset = name;
    next.preset_custom = saved?.custom || false;
    next.preset_revision = saved ? saved.revision : revision;
    next.protection_level = name.replace(/^builtin:/, '');
    // The existing strict release check requires at least two VMs. Keep that
    // explicit switch unchanged; do not silently toggle it when choosing a tier.
    return next;
  }
  function setBackend(state, backend) {
    const next = clone(state);
    next.config.vm_options ||= {};
    next.config.vm_options.backend = backend;
    return next;
  }
  const api = { applyPreset, setBackend };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PresetState = api;
})(globalThis);
