/* global hexo */
// Folds long code blocks: anything over LIMIT + SLACK lines is cut to LIMIT
// lines with a fade and a "Show all N lines" button. Loaded automatically by Hexo
// (everything in scripts/ is), so neither the theme nor any post is touched.
// Without JavaScript, or when printing, every block shows in full.
'use strict';

const LIMIT = 30;  // lines shown while folded
const SLACK = 10;  // only fold if that hides more than this many lines

hexo.extend.injector.register('body_end', `
<style>
.code-fold { position: relative; margin: 1rem 0; }
.code-fold > figure.highlight { margin: 0; overflow-y: hidden; }
.code-fold.folded::after {
  content: ""; position: absolute; left: 0; right: 0; height: 4.5em;
  bottom: var(--fold-btn-h, 2.2em); pointer-events: none; border-radius: 0 0 4px 4px;
  background: linear-gradient(to bottom, transparent, var(--fold-bg, #222));
}
.code-fold-btn {
  display: block; width: 100%; margin-top: .3em; padding: .35em 0;
  font: inherit; font-size: .85em; color: inherit; opacity: .75; cursor: pointer;
  background: none; border: 1px dashed currentColor; border-radius: 4px;
}
.code-fold-btn:hover { opacity: 1; }
@media print {
  .code-fold > figure.highlight { max-height: none !important; }
  .code-fold::after, .code-fold-btn { display: none !important; }
}
</style>
<script>
(function () {
  var LIMIT = ${LIMIT}, SLACK = ${SLACK};
  var refits = [];
  document.querySelectorAll('figure.highlight').forEach(function (fig) {
    var lines = fig.querySelectorAll('td.code .line');
    if (!lines.length) lines = fig.querySelectorAll('pre .line');
    if (lines.length <= LIMIT + SLACK) return;

    var wrap = document.createElement('div');
    wrap.className = 'code-fold folded';
    fig.parentNode.insertBefore(wrap, fig);
    wrap.appendChild(fig);
    wrap.style.setProperty('--fold-bg', getComputedStyle(fig).backgroundColor);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'code-fold-btn';
    wrap.appendChild(btn);

    // Measured rather than computed, so wrapped long lines are accounted for.
    function foldHeight() {
      var top = fig.getBoundingClientRect().top;
      var cut = lines[LIMIT - 1].getBoundingClientRect().bottom;
      return Math.ceil(cut - top) + 'px';
    }
    function set(folded) {
      wrap.classList.toggle('folded', folded);
      fig.style.maxHeight = folded ? foldHeight() : '';
      btn.textContent = folded ? 'Show all ' + lines.length + ' lines' : 'Collapse';
      btn.setAttribute('aria-expanded', String(!folded));
      wrap.style.setProperty('--fold-btn-h', (btn.offsetHeight + 4) + 'px');
    }
    btn.addEventListener('click', function () {
      var folding = !wrap.classList.contains('folded');
      set(folding);
      // After collapsing a long block, don't leave the reader far below it.
      if (folding && wrap.getBoundingClientRect().top < 0) wrap.scrollIntoView();
    });
    set(true);
    refits.push(function () { if (wrap.classList.contains('folded')) set(true); });
  });
  // Wrapped lines change height with the window width, so re-measure.
  var t;
  window.addEventListener('resize', function () {
    clearTimeout(t);
    t = setTimeout(function () { refits.forEach(function (f) { f(); }); }, 150);
  });
})();
</script>
`, 'default');
