/* Local Lua highlighting; no network, contenteditable, or source rewriting. */
(() => {
  const escape = text => text.replace(/[&<>]/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;'}[c]));
  const keywords = new Set('and break do else elseif end false for function goto if in local nil not or repeat return then true until while'.split(' '));
  const builtins = new Set('assert collectgarbage coroutine debug error getmetatable ipairs math next pairs pcall print rawequal rawget rawlen rawset require select setmetatable string table tonumber tostring type unpack utf8 xpcall _ENV _G'.split(' '));
  const pattern = /--\[(=*)\[[\s\S]*?(?:\]\1\]|$)|--[^\r\n]*|\[(=*)\[[\s\S]*?(?:\]\2\]|$)|"(?:\\[\s\S]|[^"\\])*?(?:"|$)|'(?:\\[\s\S]|[^'\\])*?(?:'|$)|\b0[xX][\da-fA-F]+(?:\.(?!\.)[\da-fA-F]*)?(?:[pP][+-]?\d+)?|(?:\b\d+(?:\.(?!\.)\d*)?|\.\d+)(?:[eE][+-]?\d+)?|\b[A-Za-z_][A-Za-z_0-9]*\b|==|~=|<=|>=|\/\/|<<|>>|\.\.|[+*%^#=<>/&|~:-]/g;

  function tokenize(text) {
    const tokens = [];
    pattern.lastIndex = 0;
    for (const match of text.matchAll(pattern)) {
      const value = match[0];
      let kind = '';
      if (value.startsWith('--')) {
        kind = 'comment';
        const marker = /^--@(?:(VM|FUNCTION_OBF|NO_VM)\b|(VM|FUNCTION_OBF|NO_VM|NO_OBF|NUMBER_OBF|MEME_STRINGS)_(START|END)\b)/.exec(value);
        if (marker
            && !text.slice(text.lastIndexOf('\n', match.index - 1) + 1, match.index).trim())
          kind = marker[3] === 'START' ? 'marker-start' : marker[3] === 'END' ? 'marker-end' : 'marker';
      }
      else if (/^["'\[]/.test(value)) kind = 'string';
      else if (/^[\d.]/.test(value) && value !== '..') kind = 'number';
      else if (keywords.has(value)) kind = 'keyword';
      else if (/^(?:STRING|NUMBER|BOOLEAN|TABLE)_OBF$/.test(value)) kind = 'marker';
      else if (builtins.has(value)) kind = 'builtin';
      else if (/^[A-Za-z_]/.test(value)) {
        if (/^\s*\(/.test(text.slice(match.index + value.length, match.index + value.length + 40))) kind = 'function';
      } else kind = 'operator';
      if (kind) tokens.push({start: match.index, end: match.index + value.length, kind});
    }
    return tokens;
  }

  function lowerBound(tokens, offset) {
    let lo = 0, hi = tokens.length;
    while (lo < hi) { const mid = (lo + hi) >>> 1; if (tokens[mid].end <= offset) lo = mid + 1; else hi = mid; }
    return lo;
  }

  function highlight(text, tokens, start, end) {
    let html = '', position = start;
    for (let index = lowerBound(tokens, start); index < tokens.length && tokens[index].start < end; index++) {
      const token = tokens[index], left = Math.max(start, token.start), right = Math.min(end, token.end);
      html += escape(text.slice(position, left));
      html += `<span class="token-${token.kind}">${escape(text.slice(left, right))}</span>`;
      position = right;
    }
    return html + escape(text.slice(position, end));
  }

  class LuaEditor {
    constructor(textarea) {
      this.input = textarea;
      this.surface = document.createElement('div');
      this.surface.className = 'code-surface';
      this.surface.classList.toggle('output-surface', textarea.readOnly);
      textarea.before(this.surface);
      this.layer = document.createElement('div');
      this.layer.className = 'highlight-layer';
      this.layer.setAttribute('aria-hidden', 'true');
      this.gutter = document.createElement('div');
      this.gutter.className = 'line-gutter';
      this.gutter.setAttribute('aria-hidden', 'true');
      this.surface.append(this.layer, this.gutter, textarea);
      this.scrollbars = ['vertical', 'horizontal'].map(axis => this.createScrollbar(axis));
      textarea.wrap = 'off';
      textarea.setAttribute('aria-label', textarea.id === 'input-script' ? 'Lua source' : 'Lua output');
      textarea.addEventListener('input', () => this.refresh());
      textarea.addEventListener('scroll', () => this.schedule());
      textarea.addEventListener('keydown', event => {
        if (event.key !== 'Tab' || textarea.readOnly || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
        event.preventDefault();
        const start = textarea.selectionStart, end = textarea.selectionEnd;
        textarea.setRangeText('  ', start, end, 'end');
        textarea.dispatchEvent(new Event('input', {bubbles: true}));
      });
      new ResizeObserver(() => this.schedule()).observe(this.surface);
      this.refresh();
    }

    setWordWrap(enabled) {
      if (this.wordWrap === enabled) return;
      this.wordWrap = enabled;
      this.surface.classList.toggle('word-wrap', enabled);
      this.input.wrap = enabled ? 'soft' : 'off';
      this.input.scrollLeft = 0;
      this.wrapTokens = null;
      if (!enabled) { this.measure?.remove(); this.measure = null; }
      this.schedule();
    }

    createScrollbar(axis) {
      const vertical = axis === 'vertical';
      const bar = document.createElement('div');
      bar.className = `editor-scrollbar ${axis}`;
      bar.setAttribute('role', 'scrollbar');
      bar.setAttribute('aria-orientation', axis);
      bar.setAttribute('aria-controls', this.input.id);
      bar.setAttribute('aria-label', `${this.input.readOnly ? 'Lua output' : 'Lua source'} ${axis} scrollbar`);
      const thumb = document.createElement('div');
      thumb.className = 'editor-scrollbar-thumb';
      bar.append(thumb);
      this.surface.append(bar);
      const position = vertical ? 'scrollTop' : 'scrollLeft';
      const coordinate = vertical ? 'clientY' : 'clientX';
      let drag;
      const move = event => {
        const rect = bar.getBoundingClientRect();
        const offset = event[coordinate] - (vertical ? rect.top : rect.left) - drag;
        this.input[position] = offset / (bar.trackSize - bar.thumbSize) * bar.maxScroll;
        this.schedule();
      };
      bar.addEventListener('pointerdown', event => {
        if (event.button !== 0 || !bar.maxScroll || bar.trackSize <= bar.thumbSize) return;
        event.preventDefault();
        const rect = thumb.getBoundingClientRect();
        const start = vertical ? rect.top : rect.left;
        const offset = event[coordinate] - start;
        drag = offset >= 0 && offset <= bar.thumbSize ? offset : bar.thumbSize / 2;
        bar.setPointerCapture(event.pointerId);
        bar.classList.add('dragging');
        move(event);
      });
      bar.addEventListener('pointermove', event => { if (drag !== undefined) move(event); });
      const release = () => { drag = undefined; bar.classList.remove('dragging'); };
      bar.addEventListener('lostpointercapture', release);
      bar.addEventListener('pointercancel', release);
      bar.addEventListener('pointerup', event => {
        if (bar.hasPointerCapture(event.pointerId)) bar.releasePointerCapture(event.pointerId);
        release();
      });
      bar.addEventListener('wheel', event => {
        if (!bar.maxScroll) return;
        event.preventDefault();
        const unit = event.deltaMode === 1 ? 24 : event.deltaMode === 2 ? (vertical ? this.input.clientHeight : this.input.clientWidth) : 1;
        this.input[position] += (vertical ? event.deltaY : event.deltaX || event.deltaY) * unit;
        this.schedule();
      }, {passive: false});
      bar.addEventListener('keydown', event => {
        const page = vertical ? this.input.clientHeight : this.input.clientWidth;
        const amount = ({ArrowUp: -24, ArrowLeft: -24, ArrowDown: 24, ArrowRight: 24, PageUp: -page, PageDown: page})[event.key];
        if (amount !== undefined || event.key === 'Home' || event.key === 'End') {
          event.preventDefault();
          this.input[position] = event.key === 'Home' ? 0 : event.key === 'End' ? bar.maxScroll : this.input[position] + amount;
          this.schedule();
        }
      });
      bar.thumb = thumb;
      bar.vertical = vertical;
      return bar;
    }

    renderScrollbars() {
      for (const bar of this.scrollbars) {
        const {vertical, thumb} = bar;
        const viewport = vertical ? this.input.clientHeight : this.input.clientWidth;
        const extent = vertical ? this.input.scrollHeight : this.input.scrollWidth;
        const position = vertical ? this.input.scrollTop : this.input.scrollLeft;
        const track = vertical ? bar.clientHeight : bar.clientWidth;
        const size = Math.min(track, Math.max(28, track * viewport / extent));
        bar.trackSize = track;
        bar.thumbSize = size;
        bar.maxScroll = Math.max(0, extent - viewport);
        thumb.style[vertical ? 'height' : 'width'] = `${size}px`;
        thumb.style[vertical ? 'top' : 'left'] = `${bar.maxScroll ? position / bar.maxScroll * (track - size) : 0}px`;
        bar.setAttribute('aria-valuemin', '0');
        bar.setAttribute('aria-valuemax', String(bar.maxScroll));
        bar.setAttribute('aria-valuenow', String(Math.round(position)));
        bar.setAttribute('aria-disabled', String(!bar.maxScroll));
        bar.tabIndex = bar.maxScroll ? 0 : -1;
      }
    }

    refresh() {
      if (this.original !== this.input.value) {
        this.original = this.input.value;
        // The transparent textarea uses the same four-column tab stops.
        this.text = this.original.split('\n').map(line => {
          let column = 0;
          return line.replace(/[^\t]*\t|[^\t]+/g, part => {
            if (!part.endsWith('\t')) { column += part.length; return part; }
            column += part.length - 1;
            const count = 4 - column % 4; column += count;
            return part.slice(0, -1) + ' '.repeat(count);
          });
        }).join('\n');
        this.tokens = tokenize(this.text);
        this.wrapTokens = null;
        this.starts = [0];
        for (let i = 0; i < this.text.length; i++) if (this.text[i] === '\n') this.starts.push(i + 1);
      }
      this.schedule();
    }

    schedule() {
      cancelAnimationFrame(this.frame);
      this.frame = requestAnimationFrame(() => this.render());
    }

    renderWrapped(style, lineHeight) {
      // A single plain text node lets the browser determine its own Unicode,
      // tab and word boundaries. Only visible visual rows get token elements;
      // even a megabyte-long minified line never becomes a full highlighted DOM.
      if (!this.measure) {
        this.measure = document.createElement('pre');
        this.measure.className = 'wrap-measure';
        this.measure.setAttribute('aria-hidden', 'true');
        this.surface.append(this.measure);
      }
      if (!this.wrapTokens) {
        this.wrapTokens = tokenize(this.original);
        this.rawStarts = [0];
        for (let i = 0; i < this.original.length; i++) if (this.original[i] === '\n') this.rawStarts.push(i + 1);
        this.measure.textContent = this.original + '\u200b';
      }
      Object.assign(this.measure.style, {width: `${this.input.clientWidth}px`, padding: style.padding,
        fontFamily: style.fontFamily, fontSize: style.fontSize, fontWeight: style.fontWeight,
        fontStyle: style.fontStyle, lineHeight: style.lineHeight, letterSpacing: style.letterSpacing});
      const range = document.createRange(), text = this.measure.firstChild, length = this.original.length;
      range.setStart(text, 0); range.setEnd(text, 1);
      const firstGlyphTop = range.getBoundingClientRect().top;
      const yAt = offset => {
        range.setStart(text, offset); range.setEnd(text, offset + 1);
        return parseFloat(style.paddingTop) + Math.round((range.getBoundingClientRect().top - firstGlyphTop) / lineHeight) * lineHeight;
      };
      const firstAt = (y, start = 0) => {
        let lo = start, hi = length + 1;
        while (lo < hi) {
          const mid = (lo + hi) >>> 1;
          if (yAt(mid) < y) lo = mid + 1; else hi = mid;
        }
        return lo;
      };
      let start = firstAt(this.input.scrollTop - 2 * lineHeight);
      let logical = 0, hi = this.rawStarts.length;
      while (logical < hi) {
        const mid = (logical + hi) >>> 1;
        if (this.rawStarts[mid] <= start) logical = mid + 1; else hi = mid;
      }
      logical = Math.max(0, logical - 1);
      const lines = [], numbers = [], count = Math.ceil(this.input.clientHeight / lineHeight) + 6;
      for (let row = 0; row < count && start <= length; row++) {
        const y = yAt(start), next = firstAt(y + lineHeight / 2, start + 1);
        let end = Math.min(next, length);
        if (this.original[end - 1] === '\n') end--;
        if (this.original[end - 1] === '\r') end--;
        const top = y - this.input.scrollTop;
        lines.push(`<pre style="top:${top}px;left:${parseFloat(style.paddingLeft)}px">${highlight(this.original, this.wrapTokens, start, end) || ' '}</pre>`);
        while (logical + 1 < this.rawStarts.length && this.rawStarts[logical + 1] <= start) logical++;
        if (this.rawStarts[logical] === start) {
          const marker = this.wrapTokens[lowerBound(this.wrapTokens, start)];
          const markerClass = marker?.start < end && ['marker-start','marker-end'].includes(marker.kind) ? ` class="${marker.kind}-line"` : '';
          numbers.push(`<span${markerClass} style="top:${top}px">${logical + 1}</span>`);
        }
        start = next;
      }
      this.layer.innerHTML = lines.join(''); this.gutter.innerHTML = numbers.join('');
    }

    render() {
      if (!this.input.clientHeight) return;
      this.renderScrollbars();
      const style = getComputedStyle(this.input);
      const lineHeight = parseFloat(style.lineHeight);
      if (this.wordWrap) { this.renderWrapped(style, lineHeight); return; }
      const paddingTop = parseFloat(style.paddingTop), paddingLeft = parseFloat(style.paddingLeft);
      const canvas = this.canvas ||= document.createElement('canvas');
      const context = canvas.getContext('2d'); context.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
      const charWidth = context.measureText('M').width;
      const firstLine = Math.max(0, Math.floor((this.input.scrollTop - paddingTop) / lineHeight));
      const lastLine = Math.min(this.starts.length, firstLine + Math.ceil(this.input.clientHeight / lineHeight) + 3);
      const firstColumn = Math.max(0, Math.floor(this.input.scrollLeft / charWidth) - 2);
      const columns = Math.ceil(this.input.clientWidth / charWidth) + 6;
      const lines = [], numbers = [];
      for (let line = firstLine; line < lastLine; line++) {
        const lineStart = this.starts[line];
        const lineEnd = line + 1 < this.starts.length ? this.starts[line + 1] - 1 : this.text.length;
        let column = firstColumn;
        let offset = column * charWidth;
        const content = this.text.slice(lineStart, lineEnd);
        // Unicode strings can occupy more than one monospace column.
        if (firstColumn && /[^\x00-\x7f]/.test(content)) {
          let lo = 0, hi = content.length;
          while (lo < hi) {
            const mid = (lo + hi + 1) >>> 1;
            if (context.measureText(content.slice(0, mid)).width < this.input.scrollLeft) lo = mid; else hi = mid - 1;
          }
          column = Math.max(0, lo - 2);
          offset = context.measureText(content.slice(0, column)).width;
        }
        const start = Math.min(lineEnd, lineStart + column), end = Math.min(lineEnd, start + columns);
        const html = highlight(this.text, this.tokens, start, end);
        const y = paddingTop + line * lineHeight - this.input.scrollTop;
        lines.push(`<pre style="top:${y}px;left:${paddingLeft + offset - this.input.scrollLeft}px">${html || ' '}</pre>`);
        const marker = this.tokens[lowerBound(this.tokens, lineStart)];
        const markerClass = marker?.start < lineEnd && ['marker-start', 'marker-end'].includes(marker.kind) ? ` class="${marker.kind}-line"` : '';
        numbers.push(`<span${markerClass} style="top:${y}px">${line + 1}</span>`);
      }
      this.layer.innerHTML = lines.join('');
      this.gutter.innerHTML = numbers.join('');
    }
  }
  window.LuaCodeEditor = {attach: input => new LuaEditor(input), tokenize};
})();
