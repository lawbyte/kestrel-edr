// Applies the saved theme before first paint. External file (not inline) so the
// server's Content-Security-Policy (script-src 'self') allows it.
try {
  var t = localStorage.getItem('kestrel-theme');
  if (t === 'light') { document.documentElement.classList.remove('dark'); document.documentElement.classList.add('light'); }
} catch (e) {}
