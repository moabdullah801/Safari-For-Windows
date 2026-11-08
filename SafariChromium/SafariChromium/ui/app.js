// Toolbar UI. Pure view: it renders state sent by main.js and sends commands back.
(() => {
  const $ = (id) => document.getElementById(id);
  const tabsEl = $('tabs');
  const address = $('address');

  let state = {
    tabs: [], groups: [], activeId: null, url: '',
    canBack: false, canForward: false, loading: false,
    isPrivate: false, maximized: false, trackersBlocked: 0, blockerOn: true,
    theme: 'system',
    downloads: [],
  };
  let editingGroup = false; // don't rebuild the tab strip while a group is being renamed
  let draggingTabId = null;

  const send = (name, payload) => window.browser.send(name, payload);

  window.browser.onState((next) => {
    state = next;
    render();
  });
  window.browser.onFocusAddress(() => {
    address.focus();
    address.select();
  });

  function shortUrl(url) {
    if (!url) return '';
    try { return new URL(url).hostname.replace(/^www\./, ''); }
    catch (_) { return url; }
  }

  function render() {
    document.body.classList.toggle('private', state.isPrivate);
    if (state.theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.dataset.theme = state.theme;

    $('back').disabled = !state.canBack;
    $('forward').disabled = !state.canForward;
    $('reload').dataset.mode = state.loading ? 'stop' : 'reload';
    $('reload').title = state.loading ? 'Stop' : 'Reload';
    $('max').textContent = '';
    $('max').innerHTML = state.maximized
      ? '<svg viewBox="0 0 10 10"><path d="M3 1.5h5.5V7M1.5 3h5.5v5.5H1.5z"/></svg>'
      : '<svg viewBox="0 0 10 10"><rect x="1.5" y="1.5" width="7" height="7"/></svg>';

    $('shield').classList.toggle('off', !state.blockerOn);
    $('shield').title = state.blockerOn
      ? `Content blocker on. Trackers blocked: ${state.trackersBlocked}. Click to turn off.`
      : 'Content blocker is off. Click to turn on.';
    $('shield-count').textContent = state.trackersBlocked;
    $('bookmark').classList.toggle('bookmarked', state.isBookmarked);
    $('bookmark').title = state.isBookmarked ? 'Remove bookmark' : 'Bookmark this page';

    if (document.activeElement !== address) address.value = shortUrl(state.url);
    renderTabs();
    renderDownloadBadge();
  }

  function renderDownloadBadge() {
    const entries = state.downloads || [];
    const pending = entries.filter((entry) => ['Downloading', 'Scanning', 'Choose save location'].includes(entry.status)).length;
    const flagged = entries.filter((entry) => entry.status === 'Flagged').length;
    const badge = $('download-badge');
    const badgeCount = pending || flagged;
    badge.hidden = badgeCount === 0;
    badge.textContent = flagged ? '!' : (pending > 9 ? '9+' : String(pending));
    $('downloads-button').classList.toggle('has-downloads', badgeCount > 0);
    $('downloads-button').classList.toggle('has-flagged-download', flagged > 0);
    $('downloads-button').title = flagged ? `${flagged} download${flagged === 1 ? '' : 's'} flagged for review` : 'Downloads';
  }

  function renderTabs() {
    if (editingGroup || draggingTabId !== null) return;
    const previousRects = new Map([...tabsEl.querySelectorAll('.tab')].map((el) => [el.dataset.tabId, el.getBoundingClientRect()]));
    tabsEl.replaceChildren();
    let lastGroupId = null;
    for (const tab of state.tabs) {
      const group = state.groups.find((g) => g.id === tab.groupId) || null;
      if (group && group.id !== lastGroupId) tabsEl.appendChild(groupLabel(group));
      lastGroupId = group ? group.id : null;
      tabsEl.appendChild(tabElement(tab, group));
    }
    for (const el of tabsEl.querySelectorAll('.tab')) {
      const previous = previousRects.get(el.dataset.tabId);
      if (!previous) continue;
      const current = el.getBoundingClientRect();
      const offsetX = previous.left - current.left;
      const offsetY = previous.top - current.top;
      if (!offsetX && !offsetY) continue;
      el.style.transition = 'none';
      el.style.transform = `translate(${offsetX}px, ${offsetY}px)`;
      el.getBoundingClientRect();
      requestAnimationFrame(() => {
        el.style.transition = '';
        el.style.transform = '';
      });
    }
    const active = tabsEl.querySelector('.tab.active');
    if (active) active.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  function tabElement(tab, group) {
    const el = document.createElement('div');
    el.className = 'tab'
      + (tab.id === state.activeId ? ' active' : '')
      + (group ? ' grouped' : '')
      + (tab.hibernated ? ' hibernated' : '');
    if (group) el.style.setProperty('--gc', group.color);
    el.title = tab.hibernated ? `${tab.title} (reloads when selected)` : tab.title;
    el.setAttribute('role', 'tab');
    el.dataset.tabId = String(tab.id);
    el.draggable = true;

    el.addEventListener('dragstart', (event) => {
      if (event.target.closest('button')) { event.preventDefault(); return; }
      draggingTabId = tab.id;
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', String(tab.id));
      requestAnimationFrame(() => el.classList.add('dragging'));
    });
    el.addEventListener('dragend', () => {
      draggingTabId = null;
      renderTabs();
    });
    el.addEventListener('dragover', (event) => {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      el.classList.add('drag-over');
    });
    el.addEventListener('dragleave', (event) => {
      if (!el.contains(event.relatedTarget)) el.classList.remove('drag-over');
    });
    el.addEventListener('drop', (event) => {
      event.preventDefault();
      event.stopPropagation();
      const sourceId = Number(event.dataTransfer.getData('text/plain')) || draggingTabId;
      el.classList.remove('drag-over');
      draggingTabId = null;
      if (sourceId !== null) send('tab:drop', { sourceId, targetId: tab.id });
    });

    el.addEventListener('click', () => send('tab:select', { id: tab.id }));
    el.addEventListener('auxclick', (event) => {
      if (event.button === 1) {
        event.preventDefault();
        send('tab:close', { id: tab.id });
      }
    });

    const icon = document.createElement('span');
    icon.className = 'tab-icon' + (tab.loading ? ' spin' : '');
    if (!tab.loading && tab.favicon) {
      const img = document.createElement('img');
      img.src = tab.favicon;
      img.alt = '';
      img.addEventListener('error', () => img.remove());
      icon.appendChild(img);
    } else if (!tab.loading) {
      icon.innerHTML = '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c2 2.2 2 9.8 0 12M8 2c-2 2.2-2 9.8 0 12"/></svg>';
    }

    const title = document.createElement('span');
    title.className = 'tab-title';
    title.textContent = tab.title || 'New Tab';

    const close = document.createElement('button');
    close.className = 'tab-close';
    close.setAttribute('aria-label', 'Close tab');
    close.textContent = '✕';
    close.addEventListener('click', (event) => {
      event.stopPropagation();
      send('tab:close', { id: tab.id });
    });

    el.append(icon, title, close);
    return el;
  }

  function groupLabel(group) {
    const el = document.createElement('div');
    el.className = 'group-label';
    el.style.setProperty('--gc', group.color);
    el.textContent = group.name;
    el.title = 'Double-click to rename';
    el.addEventListener('dragover', (event) => {
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      el.classList.add('drag-over');
    });
    el.addEventListener('dragleave', () => el.classList.remove('drag-over'));
    el.addEventListener('drop', (event) => {
      event.preventDefault();
      event.stopPropagation();
      const sourceId = Number(event.dataTransfer.getData('text/plain')) || draggingTabId;
      el.classList.remove('drag-over');
      draggingTabId = null;
      if (sourceId !== null) send('tab:drop', { sourceId, groupId: group.id });
    });

    el.addEventListener('dblclick', () => {
      editingGroup = true;
      el.contentEditable = 'true';
      el.focus();
      const range = document.createRange();
      range.selectNodeContents(el);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);

      const finish = () => {
        el.contentEditable = 'false';
        editingGroup = false;
        send('group:rename', { id: group.id, name: el.textContent });
      };
      el.addEventListener('blur', finish, { once: true });
      el.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') { event.preventDefault(); el.blur(); }
        if (event.key === 'Escape') { el.textContent = group.name; el.blur(); }
      });
    });
    return el;
  }

  tabsEl.addEventListener('dragover', (event) => {
    if (event.target === tabsEl) event.preventDefault();
  });
  tabsEl.addEventListener('drop', (event) => {
    if (event.target !== tabsEl) return;
    event.preventDefault();
    const sourceId = Number(event.dataTransfer.getData('text/plain')) || draggingTabId;
    draggingTabId = null;
    if (sourceId !== null) send('tab:drop', { sourceId });
  });

  // ---------- toolbar buttons ----------
  $('back').addEventListener('click', () => send('nav', { action: 'back' }));
  $('forward').addEventListener('click', () => send('nav', { action: 'forward' }));
  $('reload').addEventListener('click', () => send('nav', { action: state.loading ? 'stop' : 'reload' }));
  $('new-tab').addEventListener('click', () => send('tab:new'));
  $('downloads-button').addEventListener('click', () => send('open-downloads'));
  $('group-tab').addEventListener('click', () => send('group:new-active'));
  $('settings').addEventListener('click', () => send('open-settings'));
  $('extensions').addEventListener('click', (event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    send('extensions:menu', { x: rect.left, y: rect.bottom });
  });
  $('bookmark').addEventListener('click', () => send('bookmark:toggle'));
  $('passwords').addEventListener('click', (event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    send('passwords:menu', { x: rect.left, y: rect.bottom });
  });
  $('share').addEventListener('click', () => send('copy-link'));
  $('shield').addEventListener('click', () => send('toggle-blocker'));
  $('dots').addEventListener('click', (event) => {
    const r = event.currentTarget.getBoundingClientRect();
    send('menu', { x: r.left, y: r.bottom });
  });
  $('min').addEventListener('click', () => send('win', { action: 'min' }));
  $('max').addEventListener('click', () => send('win', { action: 'max' }));
  $('close').addEventListener('click', () => send('win', { action: 'close' }));

  // ---------- address bar ----------
  address.addEventListener('focus', () => {
    address.value = state.url || '';
    address.select();
  });
  address.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      send('nav', { action: 'go', value: address.value });
      address.blur();
    } else if (event.key === 'Escape') {
      address.blur();
    }
  });
  address.addEventListener('blur', () => render());
})();
