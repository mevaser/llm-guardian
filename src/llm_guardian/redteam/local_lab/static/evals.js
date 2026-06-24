let currentEvalId = null;

async function fetchEvals(selectEvalId = null) {
    try {
        const res = await fetch('/api/evals');
        const evals = await res.json();
        const list = document.getElementById('evals-list');
        list.innerHTML = '';
        
        if (evals.length === 0) {
            list.innerHTML = '<div>No eval reports found.</div>';
            document.getElementById('empty-state').style.display = 'block';
            document.getElementById('eval-details').style.display = 'none';
            return;
        }

        document.getElementById('empty-state').style.display = 'none';

        evals.forEach(ev => {
            const el = document.createElement('div');
            el.className = `run-item ${ev.eval_id === currentEvalId ? 'active' : ''}`;
            el.onclick = () => loadEval(ev.eval_id);
            
            const strategies = ev.strategies ? ev.strategies.join(', ') : 'Unknown';
            const cases = ev.cases_evaluated || 0;
            const runs = ev.runs_per_strategy || 0;
            const timeStr = ev.created_at ? new Date(ev.created_at * 1000).toLocaleString() : 'Unknown';
            
            el.innerHTML = `
                <div style="font-size:0.9em; color:#9cdcfe;">ID: ${ev.eval_id.substring(0,13)}...</div>
                <div style="font-weight:bold; margin:3px 0;">${timeStr}</div>
                <div style="font-size:0.9em; color:#888;">Strat: ${strategies}</div>
                <div style="font-size:0.9em;">Cases: ${cases} | Runs/Strat: ${runs}</div>
            `;
            list.appendChild(el);
        });
        
        if (selectEvalId && evals.some(e => e.eval_id === selectEvalId)) {
            loadEval(selectEvalId);
        } else if (evals.length > 0) {
            loadEval(evals[0].eval_id);
        }
    } catch (e) {
        document.getElementById('evals-list').innerText = 'Error loading evals.';
    }
}

async function loadEval(evalId) {
    currentEvalId = evalId;
    
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('eval-details').style.display = 'block';
    document.getElementById('eval-title').innerText = `Eval ID: ${evalId}`;
    
    // Update selection styling
    document.querySelectorAll('.run-item').forEach(el => {
        el.classList.remove('active');
        if (el.innerText.includes(evalId.substring(0,13))) {
            el.classList.add('active');
        }
    });
    
    try {
        const res = await fetch(`/api/evals/${evalId}`);
        const meta = await res.json();
        
        const runtime = meta.runtime_seconds ? meta.runtime_seconds.toFixed(1) + 's' : 'N/A';
        const strategies = meta.strategies ? meta.strategies.join(', ') : 'N/A';
        const cases = meta.cases_evaluated !== undefined ? meta.cases_evaluated : 'N/A';
        const runs = meta.runs_per_strategy !== undefined ? meta.runs_per_strategy : 'N/A';

        document.getElementById('eval-meta-grid').innerHTML = `
            <div><strong>Strategies</strong><span>${strategies}</span></div>
            <div><strong>Cases Evaluated</strong><span>${cases}</span></div>
            <div><strong>Runs per Strategy</strong><span>${runs}</span></div>
            <div><strong>Total Runtime</strong><span>${runtime}</span></div>
        `;
        
        if (meta.case_results) {
            calculateAggregates(meta.case_results);
            renderCaseResults(meta.case_results);
        } else {
            document.getElementById('agg-metrics-grid').innerHTML = '<div style="grid-column: span 4;">Metrics not available (case_results.json missing).</div>';
            document.getElementById('taxonomy-summary').innerHTML = '';
            document.getElementById('case-results-content').innerHTML = '<div>Case results data not available.</div>';
        }
        
        if (meta.failures) {
            renderFailures(meta.failures);
        } else {
            document.getElementById('failures-content').innerHTML = '<div>No failure backlog found (or eval had 100% success).</div>';
        }

        const activeTabElement = document.querySelector('.tab.active');
        if (activeTabElement) {
            const tabId = activeTabElement.getAttribute('onclick').match(/'([^']+)'/)[1];
            if (tabId === 'report' || tabId === 'case-results' || tabId === 'failures') {
                loadTabContent(evalId, tabId);
            }
        }
    } catch(e) {
        console.error(e);
    }
}

function calculateAggregates(cases) {
    const autoRuns = cases.filter(c => c.strategy === 'autonomous');
    if (autoRuns.length === 0) {
        document.getElementById('agg-metrics-grid').innerHTML = '<div style="grid-column: span 4;">No autonomous strategy data found.</div>';
        document.getElementById('taxonomy-summary').innerHTML = '';
        return;
    }

    let solved = 0;
    let totalScore = 0;
    let totalAttempts = 0;
    let totalDupRate = 0;
    let totalHintUtil = 0;
    let pass1 = 0, success1 = 0;
    let taxonomy = {};

    autoRuns.forEach(r => {
        if (r.solved) solved++;
        totalScore += r.trajectory_score || 0;
        totalAttempts += r.attempts || 0;
        totalDupRate += r.duplicate_prompt_rate || 0;
        totalHintUtil += r.hint_utilization_score || 0;
        if (r.pass_at_1) pass1++;
        if (r.success_at_1) success1++;
        
        if (!r.solved && r.main_failure_reason) {
            taxonomy[r.main_failure_reason] = (taxonomy[r.main_failure_reason] || 0) + 1;
        }
    });

    const count = autoRuns.length;
    const solvedRate = ((solved / count) * 100).toFixed(1) + '%';
    const avgScore = (totalScore / count).toFixed(1);
    const avgAttempts = (totalAttempts / count).toFixed(1);
    const dupRate = ((totalDupRate / count) * 100).toFixed(1) + '%';
    const hintUtil = ((totalHintUtil / count) * 100).toFixed(1) + '%';

    document.getElementById('agg-metrics-grid').innerHTML = `
        <div><strong>Solved Rate</strong><span style="color:#4CAF50">${solvedRate}</span></div>
        <div><strong>Trajectory Score</strong><span>${avgScore}</span></div>
        <div><strong>Hint Utilization</strong><span>${hintUtil}</span></div>
        <div><strong>Avg Attempts</strong><span>${avgAttempts}</span></div>
        <div><strong>Duplicate Rate</strong><span>${dupRate}</span></div>
        <div><strong>Pass@1 (Runs)</strong><span>${pass1}/${count}</span></div>
        <div><strong>Success@1 (Att.)</strong><span>${success1}/${count}</span></div>
        <div><strong>Total Runs</strong><span>${count}</span></div>
    `;

    let taxHtml = '<h4>Failure Taxonomy</h4>';
    if (Object.keys(taxonomy).length === 0) {
        taxHtml += '<p>No failures recorded.</p>';
    } else {
        taxHtml += '<ul>';
        for (const [reason, c] of Object.entries(taxonomy)) {
            taxHtml += `<li><strong>${reason}:</strong> ${c} runs</li>`;
        }
        taxHtml += '</ul>';
    }
    document.getElementById('taxonomy-summary').innerHTML = taxHtml;
}

function renderCaseResults(cases) {
    if (!cases || cases.length === 0) {
        document.getElementById('case-results-content').innerHTML = '<div>No case results.</div>';
        return;
    }
    
    let html = '<table><tr><th>Strategy</th><th>Case</th><th>Solved</th><th>Score</th><th>Attempts</th><th>Hint Util</th><th>Main Failure</th></tr>';
    cases.forEach(r => {
        const solvedStr = r.solved ? '<span style="color:#4CAF50">YES</span>' : '<span style="color:#f44336">NO</span>';
        const score = r.trajectory_score || 0;
        const attempts = r.attempts || 0;
        const hintUtil = ((r.hint_utilization_score || 0) * 100).toFixed(0) + '%';
        const failure = r.main_failure_reason || 'N/A';
        html += `<tr><td>${r.strategy}</td><td>${r.case_id}</td><td>${solvedStr}</td><td>${score}</td><td>${attempts}</td><td>${hintUtil}</td><td>${failure}</td></tr>`;
    });
    html += '</table>';
    document.getElementById('case-results-content').innerHTML = html;
}

function renderFailures(failures) {
    if (!failures || failures.length === 0) {
        document.getElementById('failures-content').innerHTML = '<div>No failure cases.</div>';
        return;
    }
    
    let html = '<table><tr><th>Strategy</th><th>Case</th><th>Failure Reason</th><th>Observed Failure</th><th>Recommendation</th></tr>';
    failures.forEach(f => {
        html += `<tr>
            <td>${f.strategy}</td>
            <td>${f.case_id}</td>
            <td>${f.main_failure_reason}</td>
            <td>${f.observed_failure}</td>
            <td>${f.recommended_controller_fix}</td>
        </tr>`;
    });
    html += '</table>';
    document.getElementById('failures-content').innerHTML = html;
}

async function loadTabContent(evalId, artifact) {
    if (artifact === 'summary') return; // Handled locally
    
    let elId = artifact === 'eval_report' ? 'report-content' : `${artifact}-content`;
    if (artifact === 'report') {
        artifact = 'eval_report';
        elId = 'report-content';
    } else if (artifact === 'case-results') {
        artifact = 'case_results';
        elId = 'case-results-content';
    }
    
    const el = document.getElementById(elId);
    if (!el) return;

    // Do not show loading state if already loaded to avoid flicker, unless explicitly refreshed.
    if (el.innerText === '' || el.innerText.includes('Loading')) {
        el.innerText = 'Loading...';
    }
    
    try {
        const res = await fetch(`/api/evals/${evalId}/${artifact}`);
        if (artifact === 'eval_report') {
            const text = await res.text();
            el.innerText = text;
        } else if (artifact === 'case_results') {
            const json = await res.json();
            renderCaseResults(json);
        } else if (artifact === 'failure_backlog') {
            const json = await res.json();
            renderFailures(json);
        }
    } catch (e) {
        el.innerText = `Error loading ${artifact}`;
    }
}

function showTab(event, tabName) {
    document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
    document.getElementById(`tab-${tabName}`).style.display = 'block';
    
    document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
    if (event && event.currentTarget) {
        event.currentTarget.classList.add('active');
    }

    if (currentEvalId && tabName !== 'summary') {
        let artifact = tabName;
        if (tabName === 'report') artifact = 'eval_report';
        else if (tabName === 'case-results') artifact = 'case_results';
        else if (tabName === 'failures') artifact = 'failure_backlog';
        loadTabContent(currentEvalId, artifact);
    }
}

function refreshTab(tabName) {
    if (currentEvalId) {
        let artifact = tabName;
        if (tabName === 'report') artifact = 'eval_report';
        else if (tabName === 'case-results') artifact = 'case_results';
        else if (tabName === 'failures') artifact = 'failure_backlog';
        document.getElementById(tabName === 'report' ? 'report-content' : `${tabName}-content`).innerText = 'Loading...';
        loadTabContent(currentEvalId, artifact);
    }
}

// Init
fetchEvals();

async function fetchPlannerStatus() {
    try {
        const res = await fetch('/api/planner-status');
        const data = await res.json();
        const display = document.getElementById('planner-status-display');
        if (display) {
            const keyLoaded = data.gemini_api_key_loaded ? 'yes' : 'no';
            display.innerHTML = `
                <div><strong>Planner provider:</strong> ${data.planner_provider}</div>
                <div><strong>Gemini key loaded:</strong> ${keyLoaded}</div>
            `;
        }
    } catch (e) {
        console.error('Error fetching planner status', e);
    }
}
fetchPlannerStatus();

const runGeminiBtn = document.getElementById('run-gemini-eval-btn');
if (runGeminiBtn) {
    runGeminiBtn.addEventListener('click', async () => {
        runGeminiBtn.disabled = true;
        runGeminiBtn.innerText = 'Starting...';
        const statusDiv = document.getElementById('gemini-eval-status');
        statusDiv.style.display = 'block';
        statusDiv.style.color = '#d4d4d4';
        statusDiv.innerText = 'Starting eval in background...';
        
        try {
            const res = await fetch('/api/evals/run-gemini-core8', {
                method: 'POST'
            });
            const data = await res.json();
            
            statusDiv.style.color = '#4CAF50';
            statusDiv.innerHTML = `
                ${data.message}<br>
                <div style="margin-top: 10px;">
                    <button class="btn" onclick="fetchEvals()" style="padding: 5px 10px; font-size: 0.9em; background: #0e639c;">Refresh Reports</button>
                </div>
            `;
            runGeminiBtn.innerText = 'Run Gemini Core8 Eval';
            runGeminiBtn.disabled = false;
        } catch (e) {
            statusDiv.style.color = '#f44336';
            statusDiv.innerText = 'Error starting eval.';
            runGeminiBtn.innerText = 'Run Gemini Core8 Eval';
            runGeminiBtn.disabled = false;
        }
    });
}
