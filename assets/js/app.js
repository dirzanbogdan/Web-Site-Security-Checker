(() => {
  const scanForm = document.getElementById('scanForm');
  const scanRunner = document.getElementById('scanRunner');
  const progressBar = document.getElementById('scanProgressBar');
  const progressText = document.getElementById('scanProgressText');
  const statusText = document.getElementById('scanStatusText');

  const setProgress = (pct, text) => {
    const p = Math.max(0, Math.min(100, pct));
    if (progressBar) progressBar.style.width = `${p}%`;
    if (progressText) progressText.textContent = `${p}%`;
    if (statusText && text) statusText.textContent = text;
  };

  const postForm = async (url, formData) => {
    const res = await fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' },
      body: formData
    });
    return res.json();
  };

  const runScan = async (scanId, csrfToken) => {
    setProgress(1, 'Pornire scanare...');
    for (;;) {
      const fd = new FormData();
      fd.set('action', 'run');
      fd.set('scan_id', String(scanId));
      fd.set('csrf_token', csrfToken);

      const data = await postForm('api/scan.php', fd);
      if (!data.ok) throw new Error(data.error || 'Eroare scanare.');

      setProgress(Number(data.progress || 0), 'Procesare...');

      if (data.status === 'done') {
        setProgress(100, 'Finalizat.');
        window.location.href = data.redirect || `index.php?page=scan&id=${scanId}`;
        return;
      }
      if (data.status === 'error') {
        window.location.href = data.redirect || `index.php?page=scan&id=${scanId}`;
        return;
      }
      await new Promise(r => setTimeout(r, 450));
    }
  };

  if (scanForm) {
    scanForm.addEventListener('submit', async (e) => {
      if (!scanRunner) return;
      e.preventDefault();

      scanRunner.classList.remove('d-none');
      setProgress(0, 'Validare...');

      const fd = new FormData(scanForm);
      fd.set('action', 'create');

      try {
        const data = await postForm('api/scan.php', fd);
        if (!data.ok) throw new Error(data.error || 'Eroare inițializare scanare.');

        const csrfToken = fd.get('csrf_token');
        await runScan(data.scan_id, csrfToken);
      } catch (err) {
        setProgress(0, err && err.message ? err.message : 'Eroare.');
      }
    });
  }

  if (window.WSSC_AUTO_REFRESH_SCAN_ID) {
    setTimeout(() => window.location.reload(), 1200);
  }
})();

