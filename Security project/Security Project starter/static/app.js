/* =========================================================
   Prompt Injection Detector — Dashboard Application
   ========================================================= */

'use strict';

// ---------------------------------------------------------------
// State
// ---------------------------------------------------------------
const appState = {
  results: [],          // AnalysisResult[]
  summary: { total: 0, safe: 0, malicious: 0 },
  analysing: false,
  demoInProgress: false,
  demoMode: '',
  demoCurrent: 0,
  demoTotal: 0,
};

// ---------------------------------------------------------------
// DOM references
// ---------------------------------------------------------------
const $ = (id) => document.getElementById(id);

const DOM = {
  countTotal:       $('count-total'),
  countSafe:        $('count-safe'),
  countMalicious:   $('count-malicious'),
  statusDot:        $('status-dot'),
  statusText:       $('status-text'),
  analyzeForm:      $('analyze-form'),
  promptInput:      $('prompt-input'),
  charCount:        $('char-count'),
  promptError:      $('prompt-error'),
  submitBtn:        $('submit-btn'),
  btnText:          document.querySelector('#submit-btn .btn-text'),
  btnSpinner:       document.querySelector('#submit-btn .btn-spinner'),
  analyzingIndicator: $('analyzing-indicator'),
  resultsList:      $('results-list'),
  resultsPlaceholder: $('results-placeholder'),
  resultsCount:     $('results-count'),
  scenariosContainer: $('scenarios-container'),
  runFullDemoBtn:   $('run-full-demo-btn'),
  runAllBtn:        $('run-all-scenarios-btn'),
  demoProgress:     $('demo-progress'),
  demoProgressFill: $('demo-progress-bar-fill'),
  demoProgressTrack: $('demo-progress-bar-track'),
  demoProgressText: $('demo-progress-text'),
  ratioChart:       $('ratio-chart'),
  chartLegend:      $('chart-legend'),
  tooltip:          $('global-tooltip'),
};

// ---------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatTime(isoString) {
  const d = new Date(isoString);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function confidenceClass(level) {
  if (!level) return 'med';
  const l = level.toLowerCase();
  if (l.includes('high'))   return 'high';
  if (l.includes('medium')) return 'med';
  return 'low';
}

function threatLabel(threatType) {
  switch (threatType) {
    case 'jailbreak':          return 'Jailbreak';
    case 'indirect_injection': return 'Indirect Injection';
    default:                   return 'None';
  }
}

function threatBadgeClass(category) {
  switch (category) {
    case 'jailbreak':          return 'threat-badge--jailbreak';
    case 'indirect_injection': return 'threat-badge--indirect';
    case 'safe':               return 'threat-badge--safe';
    default:                   return 'threat-badge--none';
  }
}

function bump(el) {
  el.classList.remove('count-bump');
  void el.offsetWidth; // reflow
  el.classList.add('count-bump');
}

// ---------------------------------------------------------------
// Summary counters
// ---------------------------------------------------------------

function updateSummary(summary) {
  const prev = { ...appState.summary };
  appState.summary = summary;

  if (summary.total    !== prev.total)    { DOM.countTotal.textContent    = summary.total;    bump(DOM.countTotal); }
  if (summary.safe     !== prev.safe)     { DOM.countSafe.textContent     = summary.safe;     bump(DOM.countSafe); }
  if (summary.malicious !== prev.malicious) { DOM.countMalicious.textContent = summary.malicious; bump(DOM.countMalicious); }

  DOM.resultsCount.textContent = summary.total
    ? `${summary.total} result${summary.total !== 1 ? 's' : ''}`
    : '';

  drawDonutChart(summary.safe, summary.malicious);
}

// ---------------------------------------------------------------
// Donut chart (canvas — no external library)
// ---------------------------------------------------------------

function drawDonutChart(safe, malicious) {
  const canvas = DOM.ratioChart;
  const ctx    = canvas.getContext('2d');
  const dpr    = window.devicePixelRatio || 1;
  const size   = 110;

  // HiDPI scaling
  if (canvas.dataset.scaled !== '1') {
    canvas.width  = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width  = size + 'px';
    canvas.style.height = size + 'px';
    ctx.scale(dpr, dpr);
    canvas.dataset.scaled = '1';
  }

  ctx.clearRect(0, 0, size, size);
  const cx = size / 2, cy = size / 2;
  const outerR = size / 2 - 6;
  const innerR = outerR * 0.62;
  const total  = safe + malicious;

  if (total === 0) {
    // Empty ring
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, 0, Math.PI * 2);
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = outerR - innerR;
    ctx.stroke();
    ctx.fillStyle = '#4a5568';
    ctx.font = `500 10px Inter,sans-serif`;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No data', cx, cy);
    DOM.chartLegend.innerHTML = '';
    return;
  }

  const startAngle = -Math.PI / 2;
  const gap = total > 1 ? 0.04 : 0; // small gap between segments

  function drawSegment(start, end, color, glowColor) {
    ctx.save();
    ctx.shadowColor = glowColor;
    ctx.shadowBlur  = 10;
    ctx.beginPath();
    ctx.arc(cx, cy, outerR, start, end);
    ctx.arc(cx, cy, innerR, end, start, true);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
    ctx.restore();
  }

  const safeAngle = (safe / total) * (Math.PI * 2 - gap * (malicious > 0 ? 2 : 0));
  const malAngle  = (malicious / total) * (Math.PI * 2 - gap * (safe > 0 ? 2 : 0));

  if (safe > 0) {
    drawSegment(startAngle + gap, startAngle + gap + safeAngle, '#10b981', 'rgba(16,185,129,0.5)');
  }
  if (malicious > 0) {
    const malStart = startAngle + gap + safeAngle + (safe > 0 ? gap : 0);
    drawSegment(malStart, malStart + malAngle, '#f43f5e', 'rgba(244,63,94,0.4)');
  }

  // Centre text
  const pct = Math.round((safe / total) * 100);
  ctx.fillStyle = '#f0f4ff';
  ctx.font = `800 ${Math.round(outerR * 0.38)}px Inter,sans-serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(`${pct}%`, cx, cy - 6);

  ctx.fillStyle = '#4a5568';
  ctx.font = `500 ${Math.round(outerR * 0.20)}px Inter,sans-serif`;
  ctx.fillText('safe', cx, cy + outerR * 0.28);

  DOM.chartLegend.innerHTML = `
    <div class="legend-item">
      <span class="legend-dot" style="background:#10b981;box-shadow:0 0 6px rgba(16,185,129,0.6)"></span>
      <span>Safe (${safe})</span>
    </div>
    <div class="legend-item">
      <span class="legend-dot" style="background:#f43f5e;box-shadow:0 0 6px rgba(244,63,94,0.5)"></span>
      <span>Malicious (${malicious})</span>
    </div>`;
}

// ---------------------------------------------------------------
// Result card rendering
// ---------------------------------------------------------------

function buildResultCard(result) {
  const isMalicious = result.classification === 'malicious';
  const confClass   = confidenceClass(result.confidence_level);
  const truncated   = result.truncated_prompt || result.prompt;
  const wasTruncated = result.prompt && result.prompt.length > 200;
  const threatClass = result.threat_type === 'jailbreak' ? 'result-threat--jailbreak'
                    : result.threat_type === 'indirect_injection' ? 'result-threat--indirect'
                    : '';

  const card = document.createElement('div');
  card.className = `result-card result-card--${result.classification}`;
  card.setAttribute('role', 'listitem');
  card.dataset.resultId = result.id;

  card.innerHTML = `
    <div class="result-card-header">
      <span class="result-classification result-classification--${result.classification}" aria-label="Classification: ${result.classification}">
        ${escapeHtml(result.classification.toUpperCase())}
      </span>
      <span class="result-threat ${threatClass}" aria-label="Threat type: ${threatLabel(result.threat_type)}">
        ${escapeHtml(threatLabel(result.threat_type))}
      </span>
      <span class="result-time" aria-label="Submitted at ${formatTime(result.submitted_at)}">
        ${formatTime(result.submitted_at)}
      </span>
    </div>
    <div class="result-prompt" aria-label="Prompt text">
      ${escapeHtml(truncated)}${wasTruncated ? '<span class="result-truncated-indicator"> [truncated]</span>' : ''}
    </div>
    <div class="result-confidence" aria-label="Confidence: ${result.confidence_score} — ${result.confidence_level || ''}">
      <div class="confidence-bar-track" role="presentation">
        <div
          class="confidence-bar-fill confidence-bar-fill--${confClass}"
          style="width: ${Math.round(result.confidence_score * 100)}%"
          aria-valuenow="${Math.round(result.confidence_score * 100)}"
          aria-valuemin="0"
          aria-valuemax="100"
        ></div>
      </div>
      <span class="confidence-score-value" aria-hidden="true">${result.confidence_score.toFixed(2)}</span>
      <span class="confidence-label confidence-label--${confClass}" aria-hidden="true">
        ${escapeHtml(result.confidence_level || '')}
      </span>
    </div>`;

  return card;
}

function prependResult(result) {
  // Remove placeholder if present
  if (DOM.resultsPlaceholder && DOM.resultsPlaceholder.isConnected) {
    DOM.resultsPlaceholder.remove();
  }

  const card = buildResultCard(result);
  DOM.resultsList.insertBefore(card, DOM.resultsList.firstChild);
}

function renderAllResults(results) {
  DOM.resultsList.innerHTML = '';
  if (!results || results.length === 0) {
    DOM.resultsList.appendChild(DOM.resultsPlaceholder);
    return;
  }
  results.forEach((r) => DOM.resultsList.appendChild(buildResultCard(r)));
}

// ---------------------------------------------------------------
// Demo progress bar
// ---------------------------------------------------------------

function updateDemoProgress(current, total, show) {
  if (!show) {
    DOM.demoProgress.hidden = true;
    DOM.runFullDemoBtn.disabled = false;
    DOM.runAllBtn.disabled = false;
    return;
  }

  DOM.demoProgress.hidden = false;
  DOM.runFullDemoBtn.disabled = true;
  DOM.runAllBtn.disabled = true;

  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  DOM.demoProgressFill.style.width = `${pct}%`;
  DOM.demoProgressTrack.setAttribute('aria-valuenow', pct);
  DOM.demoProgressText.textContent = `${current} / ${total} prompts`;
}

// ---------------------------------------------------------------
// Scenario panel
// ---------------------------------------------------------------

function renderScenarios(scenarios) {
  DOM.scenariosContainer.innerHTML = '';

  scenarios.forEach((scenario) => {
    const group = document.createElement('div');
    group.className = 'scenario-group';
    group.dataset.scenarioId = scenario.id;

    const header = document.createElement('button');
    header.className = 'scenario-header';
    header.setAttribute('aria-expanded', 'false');
    header.setAttribute('aria-controls', `scenario-body-${scenario.id}`);
    header.innerHTML = `
      <span aria-hidden="true">📁</span>
      <span>${escapeHtml(scenario.name)}</span>
      <span class="scenario-chevron" aria-hidden="true">▼</span>`;

    header.addEventListener('click', () => {
      const isOpen = group.classList.toggle('open');
      header.setAttribute('aria-expanded', String(isOpen));
    });

    const body = document.createElement('div');
    body.className = 'scenario-body';
    body.id = `scenario-body-${scenario.id}`;

    const desc = document.createElement('p');
    desc.className = 'scenario-description';
    desc.textContent = scenario.description;
    body.appendChild(desc);

    const list = document.createElement('div');
    list.className = 'scenario-prompt-list';

    scenario.prompts.forEach((sp) => {
      const card = document.createElement('button');
      card.className = 'scenario-prompt-card';
      card.setAttribute('aria-label', `Submit prompt: ${sp.label}`);

      const badgeCls = threatBadgeClass(sp.expected_category);
      const badgeLabel = sp.expected_category === 'indirect_injection' ? 'Indirect' : sp.expected_category;

      card.innerHTML = `
        <span class="scenario-prompt-label">${escapeHtml(sp.label)}</span>
        <span class="threat-badge ${badgeCls}" aria-label="Expected: ${sp.expected_category}">${escapeHtml(badgeLabel)}</span>`;

      // Tooltip on hover
      card.addEventListener('mouseenter', (e) => showTooltip(sp.explanation, e));
      card.addEventListener('mousemove',  (e) => moveTooltip(e));
      card.addEventListener('mouseleave', hideTooltip);
      card.addEventListener('focus',      (e) => showTooltip(sp.explanation, e));
      card.addEventListener('blur',       hideTooltip);

      card.addEventListener('click', () => submitPrompt(sp.prompt));

      list.appendChild(card);
    });

    body.appendChild(list);
    group.appendChild(header);
    group.appendChild(body);
    DOM.scenariosContainer.appendChild(group);
  });
}

// ---------------------------------------------------------------
// Tooltip
// ---------------------------------------------------------------

function showTooltip(text, event) {
  DOM.tooltip.textContent = text;
  DOM.tooltip.setAttribute('aria-hidden', 'false');
  DOM.tooltip.classList.add('visible');
  moveTooltip(event);
}

function moveTooltip(event) {
  const pad = 16;
  const tw = DOM.tooltip.offsetWidth;
  const th = DOM.tooltip.offsetHeight;
  let x = event.clientX + pad;
  let y = event.clientY + pad;

  if (x + tw > window.innerWidth  - pad) x = event.clientX - tw - pad;
  if (y + th > window.innerHeight - pad) y = event.clientY - th - pad;

  DOM.tooltip.style.left = `${x}px`;
  DOM.tooltip.style.top  = `${y}px`;
}

function hideTooltip() {
  DOM.tooltip.classList.remove('visible');
  DOM.tooltip.setAttribute('aria-hidden', 'true');
}

// ---------------------------------------------------------------
// Submit a prompt for analysis
// ---------------------------------------------------------------

async function submitPrompt(promptText) {
  if (appState.analysing) return;

  const text = (promptText ?? DOM.promptInput.value).trim();
  if (!text) {
    showFormError('Please enter a prompt to analyse.');
    return;
  }
  if (text.length > 10000) {
    showFormError('Prompt must be 10,000 characters or fewer.');
    return;
  }

  clearFormError();
  setAnalysing(true);

  try {
    const resp = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: text }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      const msg = err.detail || `Server error ${resp.status}`;
      showFormError(msg);
      return;
    }

    // Result is also delivered via SSE, but we clear the form here
    if (!promptText) {
      DOM.promptInput.value = '';
      updateCharCount('');
    }
  } catch (e) {
    showFormError('Analysis could not be completed. Please try again.');
  } finally {
    setAnalysing(false);
  }
}

function setAnalysing(active) {
  appState.analysing = active;
  DOM.analyzingIndicator.hidden = !active;
  DOM.submitBtn.disabled = active;
  DOM.btnSpinner.hidden = !active;
  DOM.btnText.textContent = active ? 'Analysing…' : 'Analyse';
}

function showFormError(msg) {
  DOM.promptError.textContent = msg;
  DOM.promptError.hidden = false;
}

function clearFormError() {
  DOM.promptError.textContent = '';
  DOM.promptError.hidden = true;
}

function updateCharCount(value) {
  const len = value.length;
  DOM.charCount.textContent = `${len.toLocaleString()} / 10,000`;
  DOM.charCount.classList.toggle('near-limit', len >= 9000 && len < 10000);
  DOM.charCount.classList.toggle('at-limit',   len >= 10000);
}

// ---------------------------------------------------------------
// Connection status
// ---------------------------------------------------------------

function setConnectionStatus(connected) {
  DOM.statusDot.className = `status-dot ${connected ? 'connected' : 'disconnected'}`;
  DOM.statusText.textContent = connected ? 'Connected' : 'Reconnecting…';
}

// ---------------------------------------------------------------
// Server-Sent Events
// ---------------------------------------------------------------

function connectSSE() {
  const es = new EventSource('/api/events');

  es.addEventListener('init', (e) => {
    setConnectionStatus(true);
    const data = JSON.parse(e.data);
    appState.demoInProgress = data.demo_in_progress;
    appState.demoMode       = data.demo_mode;
    appState.demoCurrent    = data.demo_current;
    appState.demoTotal      = data.demo_total;
    updateSummary(data.summary);
    renderAllResults(data.prompts);
    updateDemoProgress(data.demo_current, data.demo_total, data.demo_in_progress);
  });

  es.addEventListener('result', (e) => {
    const data = JSON.parse(e.data);
    appState.results.unshift(data.result);
    prependResult(data.result);
    updateSummary(data.summary);
    // Remove analysing state if the result was triggered by our own submit
    setAnalysing(false);
  });

  es.addEventListener('progress', (e) => {
    const data = JSON.parse(e.data);
    appState.demoInProgress = true;
    appState.demoCurrent    = data.current;
    appState.demoTotal      = data.total;
    appState.demoMode       = data.mode;
    updateDemoProgress(data.current, data.total, true);
  });

  es.addEventListener('demo_complete', () => {
    appState.demoInProgress = false;
    updateDemoProgress(0, 0, false);
  });

  es.addEventListener('error', (e) => {
    const data = JSON.parse(e.data);
    console.warn('Demo error event:', data.message);
  });

  es.onerror = () => {
    setConnectionStatus(false);
    es.close();
    // Reconnect after 3 seconds
    setTimeout(connectSSE, 3000);
  };
}

// ---------------------------------------------------------------
// Load scenarios from API
// ---------------------------------------------------------------

async function loadScenarios() {
  try {
    const resp = await fetch('/api/scenarios');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    renderScenarios(data.scenarios);
  } catch (e) {
    DOM.scenariosContainer.innerHTML =
      '<p class="placeholder-text">Could not load scenarios.</p>';
  }
}

// ---------------------------------------------------------------
// Demo action handlers
// ---------------------------------------------------------------

async function runFullDemo() {
  if (appState.demoInProgress) return;
  try {
    const resp = await fetch('/api/run-demo', { method: 'POST' });
    const data = await resp.json();
    if (data.status === 'started') {
      appState.demoInProgress = true;
      updateDemoProgress(0, data.total, true);
    }
  } catch (e) {
    console.error('Run Full Demo failed:', e);
  }
}

async function runAllScenarios() {
  if (appState.demoInProgress) return;
  try {
    const resp = await fetch('/api/run-all-scenarios', { method: 'POST' });
    const data = await resp.json();
    if (data.status === 'started') {
      appState.demoInProgress = true;
      updateDemoProgress(0, data.total, true);
    }
  } catch (e) {
    console.error('Run All Scenarios failed:', e);
  }
}

// ---------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------

DOM.analyzeForm.addEventListener('submit', (e) => {
  e.preventDefault();
  submitPrompt();
});

DOM.promptInput.addEventListener('input', () => {
  updateCharCount(DOM.promptInput.value);
  clearFormError();
});

DOM.runFullDemoBtn.addEventListener('click', runFullDemo);
DOM.runAllBtn.addEventListener('click', runAllScenarios);

// ---------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------

(function init() {
  drawDonutChart(0, 0);   // initial empty chart
  loadScenarios();
  connectSSE();
})();
