/* Workspace chrome only; decoding, history and context actions stay in app.js. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const root = document.documentElement;
  const splitVariables = ['--sidebar-width', '--source-width', '--source-height', '--candidates-height', '--compare-height'];
  const get = key => { try { return localStorage.getItem(key); } catch { return null; } };
  const set = (key, value) => { try { localStorage.setItem(key, value); } catch {} };
  // Migrate the old dark-first layout once; never touch drafts or server history.
  if (get('cbor.chromeVersion') !== '2') {
    set('cbor.theme', 'light');
    for (const name of splitVariables) set(`cbor.${name}`, '');
    set('cbor.chromeVersion', '2');
  }
  root.dataset.theme = get('cbor.theme') === 'dark' ? 'dark' : 'light';
  const themeMeta = document.querySelector('meta[name="theme-color"]');
  const syncTheme = () => { themeMeta.content = root.dataset.theme === 'dark' ? '#252d38' : '#ffffff'; };
  new MutationObserver(syncTheme).observe(root, {attributes: true, attributeFilter: ['data-theme']});
  syncTheme();

  const workspace = document.querySelector('.workspace');
  function expandComparison(expanded) {
    workspace.classList.toggle('compare-expanded', expanded);
    $('expandCompareButton').setAttribute('aria-pressed', String(expanded));
    $('expandCompareButton').textContent = expanded ? '解析と併記' : '比較を拡大';
  }
  $('expandCompareButton').addEventListener('click', () => expandComparison(!workspace.classList.contains('compare-expanded')));
  $('closeCompareButton').addEventListener('click', () => expandComparison(false));
  $('analyzeButton').addEventListener('click', () => expandComparison(false));
  $('newButton').addEventListener('click', () => expandComparison(false));
  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') expandComparison(false);
  });
  $('resetLayoutButton').addEventListener('click', () => {
    for (const name of splitVariables) { root.style.removeProperty(name); set(`cbor.${name}`, ''); }
    expandComparison(false);
    $('statusMessage').textContent = '画面配置を初期状態に戻しました';
  });

  // Explicit buttons and right-click share exactly the same action implementation.
  function openContext(button, target) {
    if (!target) return;
    const rect = button.getBoundingClientRect();
    target.dispatchEvent(new MouseEvent('contextmenu', {bubbles: true, cancelable: true, clientX: rect.left, clientY: rect.bottom + 3}));
  }
  $('inputMenuButton').addEventListener('click', () => openContext($('inputMenuButton'), $('sourceInput')));
  $('historyMenuButton').addEventListener('click', () => openContext($('historyMenuButton'), $('historyList').querySelector('.history-item.active')));
  $('nodeMenuButton').addEventListener('click', () => openContext($('nodeMenuButton'), $('treeView').querySelector('.tree-row.active')));
  const syncHistoryMenu = () => { $('historyMenuButton').disabled = !$('historyList').querySelector('.history-item.active'); };
  const syncNodeMenu = () => { $('nodeMenuButton').disabled = !$('treeView').querySelector('.tree-row.active'); };
  new MutationObserver(syncHistoryMenu).observe($('historyList'), {childList: true, subtree: true});
  new MutationObserver(syncNodeMenu).observe($('treeView'), {childList: true, subtree: true});

  // Roving tab focus: switching the result format does not discard the selection.
  const tabs = [...document.querySelectorAll('[role="tab"][data-view]')];
  function syncTabs() {
    for (const tab of tabs) {
      const active = tab.getAttribute('aria-selected') === 'true';
      tab.tabIndex = active ? 0 : -1;
      if (active) $('resultBody').setAttribute('aria-labelledby', tab.id);
    }
  }
  for (const tab of tabs) {
    new MutationObserver(syncTabs).observe(tab, {attributes: true, attributeFilter: ['aria-selected']});
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const index = tabs.indexOf(tab);
      const next = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs.at(-1) : tabs[(index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
      next.click(); next.focus();
    });
  }
  syncTabs();

  const history = $('historyPane');
  new MutationObserver(() => $('historyToggle').setAttribute('aria-expanded', String(history.classList.contains('open')))).observe(history, {attributes: true, attributeFilter: ['class']});
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && history.classList.contains('open') && $('contextMenu').hidden) {
      history.classList.remove('open'); $('historyToggle').focus();
    }
  });
  document.addEventListener('pointerdown', event => {
    if (!history.contains(event.target) && !event.target.closest('#historyToggle,#contextMenu')) history.classList.remove('open');
  });
  // Keep byte headers aligned with horizontal scrolling, including a narrow pane.
  $('hexView').addEventListener('scroll', () => {
    document.querySelector('.hex-labels').scrollLeft = $('hexView').scrollLeft;
  }, {passive: true});
  $('compareView').addEventListener('scroll', () => { $('compareLabels').scrollLeft = $('compareView').scrollLeft; }, {passive: true});
})();
