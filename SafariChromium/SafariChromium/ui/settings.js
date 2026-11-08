(() => {
  const $ = (selector) => document.querySelector(selector);
  const settingsStatus = $('#settings-status');
  const passwordStatus = $('#password-status');
  const settingControls = [...document.querySelectorAll('[data-setting]')];

  function setStatus(element, message, error = false) {
    element.textContent = message;
    element.classList.toggle('error', error);
  }

  async function saveSetting(control) {
    const value = control.type === 'checkbox' ? control.checked : control.value;
    const result = await window.browser.settings.save({ [control.dataset.setting]: value });
    if (!result.ok) {
      setStatus(settingsStatus, 'Could not save this setting.', true);
      return;
    }
    if (control.dataset.setting === 'theme') {
      if (value === 'system') document.documentElement.removeAttribute('data-theme');
      else document.documentElement.dataset.theme = value;
    }
    if (result.restartRequired) setStatus(settingsStatus, 'Saved. Restart Safari to apply this change.');
    else setStatus(settingsStatus, 'Saved');
  }

  async function renderPasswords() {
    const list = $('#password-list');
    list.replaceChildren();
    const entries = await window.browser.settings.listPasswords();
    if (!Array.isArray(entries)) {
      setStatus(passwordStatus, entries.error || 'Could not open the password vault.', true);
      return;
    }
    setStatus(passwordStatus, entries.length ? `${entries.length} saved password${entries.length === 1 ? '' : 's'}` : 'No saved passwords yet.');
    for (const entry of entries) {
      const row = document.createElement('div');
      row.className = 'password-row';
      const details = document.createElement('div');
      const name = document.createElement('strong');
      let host = entry.url;
      try { host = new URL(entry.url).hostname; } catch (_) { /* show the stored value */ }
      name.textContent = entry.name || host;
      const username = document.createElement('small');
      username.textContent = `${entry.username} · ${entry.url}`;
      details.append(name, username);

      const copy = document.createElement('button');
      copy.className = 'mini-button';
      copy.type = 'button';
      copy.textContent = 'Copy';
      copy.title = 'Copy password to clipboard';
      copy.addEventListener('click', async () => {
        const result = await window.browser.settings.copyPassword(entry.id);
        setStatus(passwordStatus, result.ok ? 'Password copied to clipboard.' : (result.error || 'Could not copy password.'), !result.ok);
      });
      const remove = document.createElement('button');
      remove.className = 'mini-button remove-button';
      remove.type = 'button';
      remove.textContent = 'Remove';
      remove.addEventListener('click', async () => {
        const result = await window.browser.settings.deletePassword(entry.id);
        if (result.ok) renderPasswords();
        else setStatus(passwordStatus, result.error || 'Could not remove password.', true);
      });
      row.append(details, copy, remove);
      list.append(row);
    }
  }

  window.browser.settings.get().then((settings) => {
    if (!settings) return;
    if (settings.theme === 'light' || settings.theme === 'dark') document.documentElement.dataset.theme = settings.theme;
    for (const control of settingControls) {
      control.type === 'checkbox'
        ? control.checked = settings[control.dataset.setting]
        : control.value = settings[control.dataset.setting];
      control.addEventListener('change', () => saveSetting(control));
    }
    $('#default-status').textContent = settings.defaultBrowser
      ? 'Safari has registered HTTP handling. Windows may require confirmation in Default apps.'
      : 'Choose Safari in Windows Default apps to open web links here.';
    if (!settings.secureStorageAvailable) {
      $('#vault-note').textContent = 'Password storage is unavailable until an OS-backed keychain or keyring is configured.';
      $('#import-passwords').disabled = true;
      $('#password-form button').disabled = true;
    }
    $('#default-button').addEventListener('click', async () => {
      const result = await window.browser.settings.setDefaultBrowser();
      if (!result.ok) setStatus(settingsStatus, 'Default-browser setup is available in the Windows app.', true);
    });
    renderPasswords();
  });

  $('#import-passwords').addEventListener('click', async () => {
    const result = await window.browser.settings.importPasswords();
    if (result.canceled) return;
    if (!result.ok) setStatus(passwordStatus, result.error || 'Import failed.', true);
    else {
      await renderPasswords();
      setStatus(passwordStatus, `Imported ${result.imported}; skipped ${result.skipped} duplicates.`);
    }
  });

  $('#password-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const result = await window.browser.settings.addPassword({
      url: form.get('url'), username: form.get('username'), password: form.get('password'),
    });
    if (!result.ok) setStatus(passwordStatus, result.error || 'Could not save password.', true);
    else {
      event.currentTarget.reset();
      setStatus(passwordStatus, 'Password saved in the encrypted vault.');
      renderPasswords();
    }
  });
})();