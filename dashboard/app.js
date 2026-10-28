/**
 * Regex Log Studio - Client Application Logic
 * Clean, structured regex simulation & log file analysis engine.
 */

(function () {
  'use strict';

  // =========================================================================
  // 1. REGULAR EXPRESSIONS (MATCHING PYTHON SPECIFICATION)
  // =========================================================================
  const TIMESTAMP_PATTERN = String.raw`\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]) ([01]\d|2[0-3]):[0-5]\d:[0-5]\d`;
  const OCTET_PATTERN = String.raw`(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`;
  const IPV4_PATTERN = '(' + OCTET_PATTERN + String.raw`\.){3}` + OCTET_PATTERN;
  const LEVEL_PATTERN = String.raw`\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b`;
  const STATUS_PATTERN = String.raw`[1-5]\d{2}`;
  const ERROR_ENTRY_PATTERN = '^' + TIMESTAMP_PATTERN + ' ERROR ' + STATUS_PATTERN + ' ' + IPV4_PATTERN + '$';

  const LINE_REGEX = new RegExp(
    '^(?<ts>' + TIMESTAMP_PATTERN + ') (?<level>' + LEVEL_PATTERN + ') (?<code>' + STATUS_PATTERN + ') (?<ip>' + IPV4_PATTERN + ')$'
  );
  const ERROR_REGEX = new RegExp(ERROR_ENTRY_PATTERN);

  const testExact = (pattern, str) => new RegExp('^(?:' + pattern + ')$').test(str);

  function diagnoseLine(line) {
    const parts = line.split(' ');
    if (parts.length !== 5) {
      return 'expected 5 fields: date time level code ip';
    }
    const timestamp = parts[0] + ' ' + parts[1];
    if (!testExact(TIMESTAMP_PATTERN, timestamp)) {
      return 'invalid timestamp';
    }
    if (!testExact(LEVEL_PATTERN, parts[2])) {
      return 'unknown log level';
    }
    if (!testExact(STATUS_PATTERN, parts[3])) {
      return 'invalid status code';
    }
    if (!testExact(IPV4_PATTERN, parts[4])) {
      return 'invalid IPv4 address';
    }
    return 'does not match the log format';
  }

  // =========================================================================
  // 2. PRELOADED SAMPLE LOG ENTRIES
  // =========================================================================
  const SAMPLE_LOG_ENTRIES = [
    '2026-10-28 10:15:20 INFO 200 192.168.1.10',
    '2026-10-28 10:15:48 INFO 200 192.168.1.12',
    '2026-10-28 10:16:05 ERROR 404 192.168.1.15',
    '2026-10-28 10:16:31 WARNING 301 10.0.0.5',
    '2026-10-28 10:17:42 ERROR 500 10.0.0.8',
    '2026-10-28 10:18:09 INFO 200 172.16.0.21',
    '2026-10-28 10:19:27 DEBUG 200 192.168.1.10',
    '2026-10-28 10:20:03 ERROR 404 203.0.113.45',
    '2026-10-28 10:21:15 WARNING 403 10.0.0.8',
    '2026-10-28 10:22:50 INFO 200 192.168.1.12',
    '2026-10-28 10:23:36 CRITICAL 503 172.16.0.4',
    '2026-10-28 10:24:12 ERROR 404 192.168.1.15',
    '2026-10-28 10:25:44 INFO 304 10.0.0.5',
    '2026-10-28 10:26:58 ERROR 500 172.16.0.21',
    '2026-10-28 10:27:30 INFO 200 192.168.1.300',
    '2026-10-28 25:10:00 ERROR 404 192.168.1.15'
  ].join('\n');

  // =========================================================================
  // 3. PATTERNS DATABASE & TEST BENCH PRESETS
  // =========================================================================
  const PATTERNS_DB = {
    1: {
      name: 'Regex 1: Timestamp',
      pattern: TIMESTAMP_PATTERN,
      desc: 'Matches ISO dates (YYYY-MM-DD) with valid months (01-12), days (01-31), and 24h times (00:00:00 to 23:59:59).',
      samples: [
        { text: '2026-10-28 10:15:20', label: 'Valid (Regular)' },
        { text: '2026-01-01 00:00:00', label: 'Valid (Midnight)' },
        { text: '2025-12-31 23:59:59', label: 'Valid (End of Year)' },
        { text: '2026-13-28 10:15:20', label: 'Invalid (Month 13)' },
        { text: '2026-10-32 10:15:20', label: 'Invalid (Day 32)' },
        { text: '2026-10-28 24:15:20', label: 'Invalid (Hour 24)' }
      ]
    },
    2: {
      name: 'Regex 2: IPv4 Address',
      pattern: IPV4_PATTERN,
      desc: 'Matches dotted decimal IPv4 addresses with 4 octets between 0 and 255. Prohibits leading zeros (e.g., 01).',
      samples: [
        { text: '192.168.1.10', label: 'Valid (Class C)' },
        { text: '10.0.0.8', label: 'Valid (Class A)' },
        { text: '255.255.255.255', label: 'Valid (Broadcast)' },
        { text: '256.1.1.1', label: 'Invalid (Octet 256)' },
        { text: '192.168.1', label: 'Invalid (3 Octets)' },
        { text: '192.168.01.1', label: 'Invalid (Leading 0)' }
      ]
    },
    3: {
      name: 'Regex 3: Log Level',
      pattern: LEVEL_PATTERN,
      desc: 'Matches standard uppercase severity levels: DEBUG, INFO, WARNING, ERROR, CRITICAL.',
      samples: [
        { text: 'INFO', label: 'Valid (INFO)' },
        { text: 'WARNING', label: 'Valid (WARNING)' },
        { text: 'ERROR', label: 'Valid (ERROR)' },
        { text: 'DEBUG', label: 'Valid (DEBUG)' },
        { text: 'error', label: 'Invalid (Lowercase)' },
        { text: 'FATAL', label: 'Invalid (Unknown Level)' }
      ]
    },
    4: {
      name: 'Regex 4: HTTP Status Code',
      pattern: STATUS_PATTERN,
      desc: 'Matches 3-digit numeric HTTP status codes strictly in the range 100 to 599.',
      samples: [
        { text: '200', label: 'Valid (200 OK)' },
        { text: '404', label: 'Valid (404 Not Found)' },
        { text: '500', label: 'Valid (500 Server Error)' },
        { text: '99', label: 'Invalid (2 Digits)' },
        { text: '600', label: 'Invalid (Exceeds 599)' },
        { text: '4O4', label: 'Invalid (Letter O)' }
      ]
    },
    5: {
      name: 'Regex 5: Error Entry',
      pattern: ERROR_ENTRY_PATTERN,
      desc: 'Matches a complete log line where the severity level is explicitly ERROR and all other fields are valid.',
      samples: [
        { text: '2026-10-28 10:16:05 ERROR 404 192.168.1.15', label: 'Valid ERROR Entry' },
        { text: '2026-10-28 10:17:42 ERROR 500 10.0.0.8', label: 'Valid ERROR 500' },
        { text: '2026-10-28 10:15:20 INFO 200 192.168.1.10', label: 'Rejected (Level is INFO)' },
        { text: '2026-10-28 10:16:05 ERROR 404 192.168.1.256', label: 'Rejected (Invalid IP)' }
      ]
    }
  };

  // =========================================================================
  // 4. 50 TEST CASES DATABASE
  // =========================================================================
  const TEST_CASES_DB = [
    // Suite 1: Timestamp
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-10-28 10:15:20', expected: true, note: 'Standard date & time' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-01-01 00:00:00', expected: true, note: 'Midnight boundary' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2025-12-31 23:59:59', expected: true, note: 'Year-end boundary' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-02-14 09:05:45', expected: true, note: 'Single-digit minute padded' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2024-07-15 18:30:00', expected: true, note: 'Leap year timestamp' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-13-28 10:15:20', expected: false, note: 'Month 13 out of range' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-10-32 10:15:20', expected: false, note: 'Day 32 out of range' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-10-28 24:15:20', expected: false, note: 'Hour 24 invalid' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026/10/28 10:15:20', expected: false, note: 'Slash delimiter not accepted' },
    { suiteId: 1, suiteName: 'Regex 1: Timestamp', pattern: TIMESTAMP_PATTERN, input: '2026-10-28 10:15', expected: false, note: 'Missing seconds' },

    // Suite 2: IPv4 Address
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '192.168.1.10', expected: true, note: 'Standard private IP' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '10.0.0.8', expected: true, note: 'Class A private IP' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '255.255.255.255', expected: true, note: 'Upper boundary' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '0.0.0.0', expected: true, note: 'Lower boundary' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '172.16.254.1', expected: true, note: 'Valid subnet IP' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '256.1.1.1', expected: false, note: 'Octet 256 > 255' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '192.168.1', expected: false, note: 'Only 3 octets' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '192.168.1.10.5', expected: false, note: '5 octets' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '192.168.01.1', expected: false, note: 'Leading zero in octet 01' },
    { suiteId: 2, suiteName: 'Regex 2: IPv4 Address', pattern: IPV4_PATTERN, input: '192.168.1.abc', expected: false, note: 'Non-numeric octet' },

    // Suite 3: Log Level
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'INFO', expected: true, note: 'Standard INFO' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'WARNING', expected: true, note: 'Standard WARNING' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'ERROR', expected: true, note: 'Standard ERROR' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'DEBUG', expected: true, note: 'Standard DEBUG' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'CRITICAL', expected: true, note: 'Standard CRITICAL' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'error', expected: false, note: 'Lowercase rejected' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'ERRORS', expected: false, note: 'Plural rejected' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'WARN', expected: false, note: 'Truncated level rejected' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'FATAL', expected: false, note: 'Unknown level' },
    { suiteId: 3, suiteName: 'Regex 3: Log Level', pattern: LEVEL_PATTERN, input: 'ERR0R', expected: false, note: 'Digit zero in keyword' },

    // Suite 4: Status Code
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '200', expected: true, note: '200 OK' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '404', expected: true, note: '404 Not Found' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '500', expected: true, note: '500 Server Error' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '301', expected: true, note: '301 Moved Permanently' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '503', expected: true, note: '503 Service Unavailable' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '99', expected: false, note: '2 digits only' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '600', expected: false, note: '600 exceeds 599' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '2000', expected: false, note: '4 digits' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '4O4', expected: false, note: 'Letter O instead of digit' },
    { suiteId: 4, suiteName: 'Regex 4: Status Code', pattern: STATUS_PATTERN, input: '000', expected: false, note: 'Starts with 0' },

    // Suite 5: Error Entry
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:16:05 ERROR 404 192.168.1.15', expected: true, note: 'Valid ERROR log' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:17:42 ERROR 500 10.0.0.8', expected: true, note: 'Valid ERROR log' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 11:02:19 ERROR 503 172.16.0.4', expected: true, note: 'Valid ERROR log' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-29 00:00:01 ERROR 403 203.0.113.77', expected: true, note: 'Valid ERROR log' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-11-02 23:59:59 ERROR 502 192.168.10.200', expected: true, note: 'Valid ERROR log' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:15:20 INFO 200 192.168.1.10', expected: false, note: 'Level is INFO, not ERROR' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:16:05 error 404 192.168.1.15', expected: false, note: 'Lowercase level' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:16:05 ERRORS 404 192.168.1.15', expected: false, note: 'Malformed level string' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: '2026-10-28 10:16:05 ERROR 404 192.168.1.256', expected: false, note: 'IP octet 256 invalid' },
    { suiteId: 5, suiteName: 'Regex 5: Error Entry', pattern: ERROR_ENTRY_PATTERN, input: 'ERROR 404 192.168.1.15', expected: false, note: 'Missing timestamp' }
  ];

  function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/[&<>"']/g, function (m) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
  }

  // =========================================================================
  // 5. TAB NAVIGATION
  // =========================================================================
  const navTabs = document.querySelectorAll('.nav-tab');
  const viewPanels = document.querySelectorAll('.view-panel');

  function setActiveTab(tabKey) {
    navTabs.forEach(t => {
      const isCurrent = t.dataset.tab === tabKey;
      t.classList.toggle('active', isCurrent);
      t.setAttribute('aria-selected', isCurrent ? 'true' : 'false');
    });

    viewPanels.forEach(p => {
      p.classList.toggle('active', p.id === 'tab-' + tabKey);
    });
  }

  navTabs.forEach(tab => {
    tab.addEventListener('click', () => setActiveTab(tab.dataset.tab));
  });

  // =========================================================================
  // 6. LOG ANALYZER LOGIC
  // =========================================================================
  const logInput = document.getElementById('log-input');
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnSimulateStream = document.getElementById('btn-simulate-stream');
  const btnResetSample = document.getElementById('btn-reset-sample');
  const btnQuickSample = document.getElementById('btn-quick-sample');
  const btnClearInput = document.getElementById('btn-clear-input');
  const btnUploadFile = document.getElementById('btn-upload-file');
  const fileInput = document.getElementById('file-input');

  const inputTargetCode = document.getElementById('input-target-code');
  const selectLevelFilter = document.getElementById('select-level-filter');
  const tableSearch = document.getElementById('table-search');

  // Stats
  const statTotal = document.getElementById('stat-total');
  const statValid = document.getElementById('stat-valid');
  const statValidRate = document.getElementById('stat-valid-rate');
  const statInvalid = document.getElementById('stat-invalid');
  const statErrors = document.getElementById('stat-errors');
  const statCodeTitle = document.getElementById('stat-code-title');
  const statCodeCount = document.getElementById('stat-code-count');
  const statUniqueIps = document.getElementById('stat-unique-ips');

  const distributionTrack = document.getElementById('distribution-track');
  const levelLegend = document.getElementById('level-legend');
  const tableRecordsBody = document.getElementById('table-records-body');
  const tableCountBadge = document.getElementById('table-count-badge');
  const invalidList = document.getElementById('invalid-list');
  const invalidCountBadge = document.getElementById('invalid-count-badge');

  let currentAnalysisData = null;
  let streamTimer = null;
  let isStreamActive = false;

  function runLogAnalysis(rawContent, targetCode) {
    const rawLines = rawContent.split('\n').map(l => l.replace(/\r$/, '')).filter(l => l.trim() !== '');
    const validRecords = [];
    const invalidRecords = [];
    const levelDistribution = { INFO: 0, ERROR: 0, WARNING: 0, DEBUG: 0, CRITICAL: 0 };
    const ipCollection = new Set();
    let errorEntryTotal = 0;

    rawLines.forEach((lineText, index) => {
      const lineNumber = index + 1;
      const match = LINE_REGEX.exec(lineText);

      if (match && match.groups) {
        const { ts, level, code, ip } = match.groups;
        const isError = ERROR_REGEX.test(lineText);

        if (isError) errorEntryTotal++;
        if (levelDistribution[level] !== undefined) levelDistribution[level]++;
        ipCollection.add(ip);

        validRecords.push({
          line: lineNumber,
          raw: lineText,
          timestamp: ts,
          level,
          code,
          ip,
          isError
        });
      } else {
        invalidRecords.push({
          line: lineNumber,
          raw: lineText,
          reason: diagnoseLine(lineText)
        });
      }
    });

    const targetCodeTotal = validRecords.filter(r => r.code === targetCode).length;

    return {
      total: rawLines.length,
      validRecords,
      invalidRecords,
      errorEntryTotal,
      levelDistribution,
      targetCodeTotal,
      targetCode,
      uniqueIpsTotal: ipCollection.size
    };
  }

  function displayAnalysis(analysis) {
    currentAnalysisData = analysis;

    // Metrics
    statTotal.textContent = analysis.total;
    statValid.textContent = analysis.validRecords.length;
    const rateVal = analysis.total > 0 ? ((analysis.validRecords.length / analysis.total) * 100).toFixed(1) : '0.0';
    statValidRate.textContent = rateVal + '%';
    statInvalid.textContent = analysis.invalidRecords.length;
    statErrors.textContent = analysis.errorEntryTotal;
    statCodeTitle.textContent = `Status ${analysis.targetCode} Matches`;
    statCodeCount.textContent = analysis.targetCodeTotal;
    statUniqueIps.textContent = analysis.uniqueIpsTotal;

    // Distribution
    renderDistribution(analysis.levelDistribution, analysis.validRecords.length);

    // Table
    renderRecords();

    // Invalid Lines
    renderInvalidLines(analysis.invalidRecords);
  }

  function renderDistribution(counts, totalValid) {
    distributionTrack.innerHTML = '';
    levelLegend.innerHTML = '';

    const levelColorMap = {
      INFO: '#2563eb',
      ERROR: '#dc2626',
      WARNING: '#d97706',
      DEBUG: '#7c3aed',
      CRITICAL: '#991b1b'
    };

    Object.entries(counts).forEach(([levelKey, count]) => {
      const pct = totalValid > 0 ? ((count / totalValid) * 100).toFixed(1) : 0;
      if (count > 0) {
        const segment = document.createElement('div');
        segment.className = 'dist-bar-seg';
        segment.style.width = pct + '%';
        segment.style.backgroundColor = levelColorMap[levelKey];
        segment.setAttribute('data-tip', `${levelKey}: ${count} (${pct}%)`);
        distributionTrack.appendChild(segment);
      }

      const legendItem = document.createElement('div');
      legendItem.className = 'legend-point';
      legendItem.innerHTML = `
        <span class="legend-dot" style="background-color: ${levelColorMap[levelKey]}"></span>
        <span>${levelKey}: ${count}</span>
      `;
      levelLegend.appendChild(legendItem);
    });
  }

  function getStatusClass(code) {
    if (code.startsWith('2')) return 'c-2xx';
    if (code.startsWith('3')) return 'c-3xx';
    if (code.startsWith('4')) return 'c-4xx';
    if (code.startsWith('5')) return 'c-5xx';
    return '';
  }

  function renderRecords() {
    if (!currentAnalysisData) return;

    const levelChoice = selectLevelFilter.value;
    const searchVal = tableSearch.value.toLowerCase().trim();

    const filtered = currentAnalysisData.validRecords.filter(r => {
      const matchLevel = levelChoice === 'ALL' || r.level === levelChoice;
      const matchSearch = !searchVal ||
        r.raw.toLowerCase().includes(searchVal) ||
        r.ip.toLowerCase().includes(searchVal);
      return matchLevel && matchSearch;
    });

    tableCountBadge.textContent = `${filtered.length} of ${currentAnalysisData.validRecords.length} records`;

    tableRecordsBody.innerHTML = filtered.map(r => `
      <tr class="${r.isError ? 'row-danger' : ''}">
        <td>#${r.line}</td>
        <td>${escapeHtml(r.timestamp)}</td>
        <td><span class="badge">${r.level}</span></td>
        <td><span class="status-code-tag ${getStatusClass(r.code)}">${r.code}</span></td>
        <td>${escapeHtml(r.ip)}</td>
        <td>${r.isError ? '<span class="badge badge-danger">ERROR Entry</span>' : '<span class="text-muted">Standard</span>'}</td>
        <td style="text-align: right;">
          <button class="btn btn-outline btn-sm inspect-btn" data-line="${escapeHtml(r.raw)}">Inspect</button>
        </td>
      </tr>
    `).join('');

    document.querySelectorAll('.inspect-btn').forEach(b => {
      b.addEventListener('click', (e) => {
        const line = e.currentTarget.dataset.line;
        inspectLine(line);
        setActiveTab('inspector');
      });
    });
  }

  function renderInvalidLines(invalidListArray) {
    if (invalidListArray.length === 0) {
      invalidCountBadge.textContent = '0 lines';
      invalidCountBadge.className = 'badge badge-success';
      invalidList.innerHTML = '<p class="text-muted" style="font-size:12.5px;">No syntax errors detected. All log lines are valid.</p>';
      return;
    }

    invalidCountBadge.textContent = `${invalidListArray.length} lines`;
    invalidCountBadge.className = 'badge badge-warning';

    invalidList.innerHTML = invalidListArray.map(item => `
      <div class="invalid-item">
        <div>
          <b>Line ${item.line}:</b>
          <span class="invalid-code">${escapeHtml(item.raw)}</span>
        </div>
        <div class="invalid-reason">
          Reason: ${escapeHtml(item.reason)}
        </div>
      </div>
    `).join('');
  }

  function executeAnalysis() {
    const text = logInput.value;
    const targetCode = inputTargetCode.value.trim() || '404';
    const analysis = runLogAnalysis(text, targetCode);
    displayAnalysis(analysis);
  }

  btnAnalyze.addEventListener('click', executeAnalysis);
  inputTargetCode.addEventListener('input', executeAnalysis);
  selectLevelFilter.addEventListener('change', renderRecords);
  tableSearch.addEventListener('input', renderRecords);

  btnResetSample.addEventListener('click', () => {
    logInput.value = SAMPLE_LOG_ENTRIES;
    executeAnalysis();
  });

  btnQuickSample.addEventListener('click', () => {
    logInput.value = SAMPLE_LOG_ENTRIES;
    executeAnalysis();
    setActiveTab('analyzer');
  });

  btnClearInput.addEventListener('click', () => {
    logInput.value = '';
    executeAnalysis();
  });

  btnUploadFile.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        logInput.value = event.target.result;
        executeAnalysis();
      };
      reader.readAsText(file);
    }
  });

  // Streaming Ingestion Simulation
  const streamBanner = document.getElementById('stream-banner');
  const streamLineCur = document.getElementById('stream-line-cur');
  const streamLineTotal = document.getElementById('stream-line-total');
  const streamProgressBar = document.getElementById('stream-progress-bar');
  const streamBtnText = document.getElementById('stream-btn-text');

  btnSimulateStream.addEventListener('click', () => {
    if (isStreamActive) {
      haltStreaming();
    } else {
      initiateStreaming();
    }
  });

  function initiateStreaming() {
    const fullText = logInput.value.trim();
    if (!fullText) return;

    const allLines = fullText.split('\n').filter(l => l.trim() !== '');
    if (allLines.length === 0) return;

    isStreamActive = true;
    streamBtnText.textContent = 'Pause Ingestion';
    streamBanner.classList.remove('hidden');
    streamLineTotal.textContent = allLines.length;

    let index = 0;
    const streamBuffer = [];

    streamTimer = setInterval(() => {
      if (index >= allLines.length) {
        haltStreaming();
        return;
      }

      streamBuffer.push(allLines[index]);
      index++;

      streamLineCur.textContent = index;
      const pct = ((index / allLines.length) * 100).toFixed(0);
      streamProgressBar.style.width = pct + '%';

      const target = inputTargetCode.value.trim() || '404';
      const partial = runLogAnalysis(streamBuffer.join('\n'), target);
      displayAnalysis(partial);
    }, 300);
  }

  function haltStreaming() {
    isStreamActive = false;
    clearInterval(streamTimer);
    streamBtnText.textContent = 'Simulate Real-Time Ingestion';
    setTimeout(() => {
      streamBanner.classList.add('hidden');
    }, 1200);
  }

  // =========================================================================
  // 7. PATTERN SIMULATOR LOGIC
  // =========================================================================
  const patternButtons = document.querySelectorAll('.pattern-btn');
  const simPatName = document.getElementById('sim-pat-name');
  const simPatRegex = document.getElementById('sim-pat-regex');
  const simPatDesc = document.getElementById('sim-pat-desc');
  const simTestInput = document.getElementById('sim-test-input');
  const simResultIndicator = document.getElementById('sim-result-indicator');
  const simPresetChips = document.getElementById('sim-preset-chips');
  const simDiagStatus = document.getElementById('sim-diag-status');
  const simDiagDetail = document.getElementById('sim-diag-detail');

  let activePatternId = 1;

  function loadPattern(patternId) {
    activePatternId = patternId;
    patternButtons.forEach(btn => {
      btn.classList.toggle('active', parseInt(btn.dataset.patternId, 10) === patternId);
    });

    const info = PATTERNS_DB[patternId];
    simPatName.textContent = info.name;
    simPatRegex.textContent = info.pattern;
    simPatDesc.textContent = info.desc;

    // Load presets
    simPresetChips.innerHTML = info.samples.map(s => `
      <button class="chip-btn" data-val="${escapeHtml(s.text)}">${escapeHtml(s.label)}</button>
    `).join('');

    simPresetChips.querySelectorAll('.chip-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        simTestInput.value = btn.dataset.val;
        evaluateSimInput();
      });
    });

    // Default input to first sample
    if (info.samples.length > 0) {
      simTestInput.value = info.samples[0].text;
    }

    evaluateSimInput();
  }

  function evaluateSimInput() {
    const info = PATTERNS_DB[activePatternId];
    const textVal = simTestInput.value;
    const isMatched = testExact(info.pattern, textVal);

    if (isMatched) {
      simResultIndicator.className = 'result-indicator valid';
      simResultIndicator.textContent = 'MATCH';
      simDiagStatus.className = 'diag-status text-success';
      simDiagStatus.textContent = 'Valid string recognized by regex';
      simDiagDetail.textContent = 'The input string strictly matches the language defined by this regular expression.';
    } else {
      simResultIndicator.className = 'result-indicator invalid';
      simResultIndicator.textContent = 'NO MATCH';
      simDiagStatus.className = 'diag-status text-danger';
      simDiagStatus.textContent = 'Rejected: Syntax does not match';
      simDiagDetail.textContent = 'The input string contains characters, boundaries, or values outside the allowed regular language.';
    }
  }

  patternButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      loadPattern(parseInt(btn.dataset.patternId, 10));
    });
  });

  simTestInput.addEventListener('input', evaluateSimInput);

  // =========================================================================
  // 8. SINGLE LINE INSPECTOR LOGIC
  // =========================================================================
  const inspectorLineInput = document.getElementById('inspector-line-input');
  const btnInspectAction = document.getElementById('btn-inspect-action');
  const inspectorBanner = document.getElementById('inspector-banner');
  const inspectorBadge = document.getElementById('inspector-badge');
  const inspectorHeading = document.getElementById('inspector-heading');
  const inspectorSub = document.getElementById('inspector-sub');

  const fcardTs = document.getElementById('fcard-ts');
  const fcardLevel = document.getElementById('fcard-level');
  const fcardCode = document.getElementById('fcard-code');
  const fcardIp = document.getElementById('fcard-ip');
  const fcardError = document.getElementById('fcard-error');

  const fstatusTs = document.getElementById('fstatus-ts');
  const fstatusLevel = document.getElementById('fstatus-level');
  const fstatusCode = document.getElementById('fstatus-code');
  const fstatusIp = document.getElementById('fstatus-ip');
  const fstatusError = document.getElementById('fstatus-error');

  const fvalTs = document.getElementById('fval-ts');
  const fvalLevel = document.getElementById('fval-level');
  const fvalCode = document.getElementById('fval-code');
  const fvalIp = document.getElementById('fval-ip');
  const fvalError = document.getElementById('fval-error');

  const fnoteTs = document.getElementById('fnote-ts');
  const fnoteLevel = document.getElementById('fnote-level');
  const fnoteCode = document.getElementById('fnote-code');
  const fnoteIp = document.getElementById('fnote-ip');
  const fnoteError = document.getElementById('fnote-error');

  function inspectLine(rawText) {
    inspectorLineInput.value = rawText;
    const cleaned = rawText.trim();
    const parts = cleaned.split(' ');

    const isValid = LINE_REGEX.test(cleaned);
    const isError = ERROR_REGEX.test(cleaned);

    // Banner
    if (isValid) {
      inspectorBanner.className = 'status-banner valid';
      inspectorBadge.textContent = 'VALID';
      inspectorHeading.textContent = isError ? 'Valid ERROR Entry' : 'Valid Standard Log Record';
      inspectorSub.textContent = isError
        ? 'Matches full line format and triggers ERROR severity alert.'
        : 'All 4 sub-fields strictly satisfy the regular expressions.';
    } else {
      inspectorBanner.className = 'status-banner invalid';
      inspectorBadge.textContent = 'INVALID';
      inspectorHeading.textContent = 'Invalid Log Entry';
      inspectorSub.textContent = `Diagnostic Failure: ${diagnoseLine(cleaned)}`;
    }

    // Timestamp
    const tsStr = (parts.length >= 2) ? `${parts[0]} ${parts[1]}` : '';
    const tsOk = testExact(TIMESTAMP_PATTERN, tsStr);
    fvalTs.textContent = tsStr || 'Missing';
    fstatusTs.textContent = tsOk ? 'Valid' : 'Failed';
    fstatusTs.className = `fcard-status ${tsOk ? 'text-success' : 'text-danger'}`;
    fcardTs.className = `field-card ${tsOk ? 'is-valid' : 'is-invalid'}`;
    fnoteTs.textContent = tsOk ? 'Valid ISO 8601 date and time' : 'Invalid date, month, hour, or format';

    // Level
    const lvlStr = parts[2] || '';
    const lvlOk = testExact(LEVEL_PATTERN, lvlStr);
    fvalLevel.textContent = lvlStr || 'Missing';
    fstatusLevel.textContent = lvlOk ? 'Valid' : 'Failed';
    fstatusLevel.className = `fcard-status ${lvlOk ? 'text-success' : 'text-danger'}`;
    fcardLevel.className = `field-card ${lvlOk ? 'is-valid' : 'is-invalid'}`;
    fnoteLevel.textContent = lvlOk ? 'Recognized level' : 'Unknown severity keyword';

    // Status Code
    const codeStr = parts[3] || '';
    const codeOk = testExact(STATUS_PATTERN, codeStr);
    fvalCode.textContent = codeStr || 'Missing';
    fstatusCode.textContent = codeOk ? 'Valid' : 'Failed';
    fstatusCode.className = `fcard-status ${codeOk ? 'text-success' : 'text-danger'}`;
    fcardCode.className = `field-card ${codeOk ? 'is-valid' : 'is-invalid'}`;
    fnoteCode.textContent = codeOk ? 'Valid 100-599 range' : 'Out of range or non-digit';

    // IP Address
    const ipStr = parts[4] || '';
    const ipOk = testExact(IPV4_PATTERN, ipStr);
    fvalIp.textContent = ipStr || 'Missing';
    fstatusIp.textContent = ipOk ? 'Valid' : 'Failed';
    fstatusIp.className = `fcard-status ${ipOk ? 'text-success' : 'text-danger'}`;
    fcardIp.className = `field-card ${ipOk ? 'is-valid' : 'is-invalid'}`;
    fnoteIp.textContent = ipOk ? 'Valid 4 octets (0-255)' : 'Malformed octet or leading zero';

    // Error Entry
    fvalError.textContent = isError ? 'YES' : 'NO';
    fstatusError.textContent = isError ? 'Matched' : 'Unmatched';
    fstatusError.className = `fcard-status ${isError ? 'text-danger' : 'text-muted'}`;
    fcardError.className = `field-card ${isError ? 'is-invalid' : ''}`;
    fnoteError.textContent = isError ? 'High-priority ERROR line' : 'Non-error log event';
  }

  btnInspectAction.addEventListener('click', () => {
    inspectLine(inspectorLineInput.value);
  });

  inspectorLineInput.addEventListener('input', () => {
    inspectLine(inspectorLineInput.value);
  });

  document.querySelectorAll('[data-preset]').forEach(btn => {
    btn.addEventListener('click', () => {
      inspectLine(btn.dataset.preset);
    });
  });

  // =========================================================================
  // 9. 50 TEST CASES SUITE LOGIC
  // =========================================================================
  const tableTestsBody = document.getElementById('table-tests-body');
  const testTabButtons = document.querySelectorAll('.test-tab-btn');
  const btnRunAllTests = document.getElementById('btn-run-all-tests');
  const testPassedStat = document.getElementById('test-passed-stat');
  const testRateStat = document.getElementById('test-rate-stat');
  const testFailedStat = document.getElementById('test-failed-stat');
  const testChipCount = document.getElementById('test-chip-count');

  let currentSuiteFilter = 'all';

  function executeTests() {
    let total = 0;
    let passedCount = 0;

    const evaluated = TEST_CASES_DB.map(tc => {
      total++;
      const actualResult = testExact(tc.pattern, tc.input);
      const isPass = actualResult === tc.expected;
      if (isPass) passedCount++;

      return {
        ...tc,
        actual: actualResult,
        passed: isPass
      };
    });

    testPassedStat.textContent = `${passedCount} / ${total}`;
    testRateStat.textContent = ((passedCount / total) * 100).toFixed(1) + '%';
    testFailedStat.textContent = total - passedCount;
    testChipCount.textContent = `${passedCount}/${total}`;

    renderTestRows(evaluated);
  }

  function renderTestRows(items) {
    const filtered = currentSuiteFilter === 'all'
      ? items
      : items.filter(tc => tc.suiteId === parseInt(currentSuiteFilter, 10));

    tableTestsBody.innerHTML = filtered.map((tc, idx) => `
      <tr>
        <td>#${idx + 1}</td>
        <td><b>${escapeHtml(tc.suiteName)}</b></td>
        <td><code>${escapeHtml(tc.input)}</code></td>
        <td><span class="badge ${tc.expected ? 'badge-success' : 'badge-danger'}">${tc.expected ? 'Valid' : 'Invalid'}</span></td>
        <td><span class="badge ${tc.actual ? 'badge-success' : 'badge-danger'}">${tc.actual ? 'Valid' : 'Invalid'}</span></td>
        <td><span class="text-muted" style="font-size:11.5px;">${escapeHtml(tc.note)}</span></td>
        <td><span class="badge ${tc.passed ? 'badge-success' : 'badge-danger'}">${tc.passed ? 'PASS' : 'FAIL'}</span></td>
      </tr>
    `).join('');
  }

  testTabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      testTabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentSuiteFilter = btn.dataset.suite;
      executeTests();
    });
  });

  btnRunAllTests.addEventListener('click', executeTests);

  // =========================================================================
  // 10. INITIALIZATION
  // =========================================================================
  function init() {
    logInput.value = SAMPLE_LOG_ENTRIES;
    executeAnalysis();
    loadPattern(1);
    inspectLine('2026-10-28 10:16:05 ERROR 404 192.168.1.15');
    executeTests();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
