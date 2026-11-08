(() => {
  const list = document.getElementById('download-list');
  const empty = document.getElementById('empty-state');
  const theme = new URLSearchParams(location.search).get('theme') || 'system';
  if (theme !== 'system') document.documentElement.dataset.theme = theme;

  function button(label, action, id, destructive = false) {
    const element = document.createElement('button');
    element.className = destructive ? 'action-button destructive' : 'action-button';
    element.type = 'button';
    element.textContent = label;
    element.addEventListener('click', () => window.browser.downloads.send(action, { id }));
    return element;
  }

  function render(entries) {
    list.replaceChildren();
    empty.hidden = entries.length > 0;
    for (const entry of entries.slice().reverse()) {
      const row = document.createElement('article');
      row.className = `download-row${entry.status === 'Flagged' ? ' flagged' : ''}`;

      const titleRow = document.createElement('div');
      titleRow.className = 'title-row';
      const name = document.createElement('strong');
      name.textContent = entry.filename;
      const state = document.createElement('span');
      state.className = 'download-state';
      state.textContent = entry.status === 'Downloading' && entry.totalBytes
        ? `Downloading · ${entry.percent}%`
        : entry.status;
      titleRow.append(name, state);
      row.append(titleRow);

      if (['Downloading', 'Choose save location'].includes(entry.status) && entry.totalBytes > 0) {
        const progress = document.createElement('progress');
        progress.max = 100;
        progress.value = entry.percent;
        row.append(progress);
      }

      if (entry.scanDetail) {
        const detail = document.createElement('p');
        detail.className = entry.status === 'Flagged' ? 'scan-warning' : 'scan-detail';
        detail.textContent = entry.scanDetail;
        row.append(detail);
      }
      if (entry.sha256) {
        const hash = document.createElement('small');
        hash.className = 'hash';
        hash.textContent = `SHA-256: ${entry.sha256}`;
        row.append(hash);
      }

      const actions = document.createElement('div');
      actions.className = 'download-actions';
      if (['Downloading', 'Choose save location'].includes(entry.status)) {
        actions.append(button('Cancel', 'cancel', entry.id, true));
      } else if (entry.status === 'Complete') {
        actions.append(button('Open', 'open', entry.id));
        actions.append(button('Show in folder', 'show', entry.id));
      }
      if (actions.childElementCount) row.append(actions);
      list.append(row);
    }
  }

  window.browser.downloads.onState(render);
  document.getElementById('clear-downloads').addEventListener('click', () => {
    window.browser.downloads.send('clear');
  });
})();