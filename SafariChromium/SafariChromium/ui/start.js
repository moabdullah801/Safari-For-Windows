(() => {
  const query = new URLSearchParams(location.search);
  const theme = query.get('theme') || 'system';
  if (theme !== 'system') document.documentElement.dataset.theme = theme;

  const engines = {
    google: ['Google', 'https://www.google.com/search'],
    duckduckgo: ['DuckDuckGo', 'https://duckduckgo.com/'],
    bing: ['Bing', 'https://www.bing.com/search'],
  };
  const [name, action] = engines.get(query.get('search')) || engines.get('google');
  document.getElementById('search-form').action = action;
  document.getElementById('engine-label').textContent = name;
})();