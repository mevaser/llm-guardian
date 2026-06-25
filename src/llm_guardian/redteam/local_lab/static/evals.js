let currentEvalId = null;
let currentEvalMeta = null;
let allEvals = [];


async function fetchEvals(selectEvalId = null) {
    try {
        const res = await fetch('/api/evals');
        allEvals = await res.json();
        renderEvalList(selectEvalId);
    } catch (e) {
        document.getElementById('evals-list').innerText = 'Error loading evals.';
    }
}



function renderEvalList(selectEvalId = null) {
    const list = document.getElementById('evals-list');
    list.innerHTML = '';

    let filtered = allEvals;

    if (filtered.length === 0) {
        list.innerHTML = '<div>No eval reports found.</div>';
        if (!currentEvalId) {
            document.getElementById('empty-state').style.display = 'block';
            document.getElementById('eval-details').style.display = 'none';
        }
        return;
    }

    filtered.forEach(ev => {
        const el = document.createElement('div');
        el.className = `run-item ${ev.eval_id === currentEvalId ? 'active' : ''}`;
        el.onclick = () => loadEval(ev.eval_id);

        const strategies = ev.strategies ? ev.strategies.join(', ') : 'Unknown';
        const cases = ev.cases_evaluated || 0;
        const runs = ev.runs_per_strategy || 0;
        const timeStr = ev.created_at ? new Date(ev.created_at * 1000).toLocaleString() : 'Unknown';
        const evalType = ev.eval_type || 'Unknown';
        const solvedCount = ev.levels_solved || 0;

        let casesHtml = `Cases: ${cases} | Solved: ${solvedCount}/${cases}`;

        if (ev.success_at_6_total > 0) {
            casesHtml += `<br>Success@6: ${ev.success_at_6_count}/${ev.success_at_6_total}`;
        } else {
            casesHtml += `<br>Eval Repetitions: ${runs}`;
        }

        const badgeHtml = ev.recommended_demo ? `<span style="background:#094771;color:#fff;padding:2px 4px;border-radius:3px;font-size:0.8em;margin-left:5px;">Recommended Demo</span>` : '';

        el.innerHTML = `
            <div style="font-size:0.9em; color:#9cdcfe; display:flex; justify-content:space-between; align-items:center;">
                <span>ID: ${ev.eval_id.substring(0, 13)}...</span>
                ${badgeHtml}
            </div>
            <div style="font-weight:bold; margin:3px 0;">${timeStr}</div>
            <div style="font-size:0.9em; color:#e2c08d; margin-bottom: 2px;">Type: ${evalType}</div>
            <div style="font-size:0.9em; color:#888;">Strat: ${strategies}</div>
            <div style="font-size:0.9em;">${casesHtml}</div>
        `;
        list.appendChild(el);
    });

    // Auto-select logic
    if (selectEvalId && filtered.some(e => e.eval_id === selectEvalId)) {
        loadEval(selectEvalId);
    } else if (!currentEvalId || !filtered.some(e => e.eval_id === currentEvalId)) {
        let toSelect = null;

        let c8demo = filtered.filter(e => e.eval_type === 'Core8 Benchmark' && e.recommended_demo);
        if (c8demo.length > 0) toSelect = c8demo[0];

        if (!toSelect) {
            let mldemo = filtered.filter(e => e.eval_type === 'Autonomous Multi-Level Run' && e.recommended_demo);
            if (mldemo.length > 0) toSelect = mldemo[0];
        }

        if (!toSelect) {
            let completed = filtered.filter(e => e.status === 'completed');
            if (completed.length > 0) toSelect = completed[0];
        }

        if (!toSelect && filtered.length > 0) {
            toSelect = filtered[0];
        }

        if (toSelect) {
            loadEval(toSelect.eval_id);
        } else {
            document.getElementById('empty-state').style.display = 'block';
            document.getElementById('eval-details').style.display = 'none';
        }
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
        if (el.innerText.includes(evalId.substring(0, 13))) {
            el.classList.add('active');
        }
    });

    try {
        const res = await fetch(`/api/evals/${evalId}`);
        const meta = await res.json();
        currentEvalMeta = meta;

        const runtime = meta.runtime_seconds ? meta.runtime_seconds.toFixed(1) + 's' : 'N/A';
        const strategies = meta.strategies ? meta.strategies.join(', ') : 'N/A';
        const cases = meta.cases_evaluated !== undefined ? meta.cases_evaluated : 'N/A';
        const runs = meta.runs_per_strategy !== undefined ? meta.runs_per_strategy : 'N/A';

        document.getElementById('eval-meta-grid').innerHTML = `
            <div><strong>Strategies</strong><span>${strategies}</span></div>
            <div><strong>Cases Evaluated</strong><span>${cases}</span></div>
            <div title="Number of times the full case set was repeated for each strategy. This is not the number of attempts inside a case."><strong>Eval Repetitions</strong><span style="border-bottom: 1px dotted #888; cursor: help;">${runs}</span></div>
            <div><strong>Total Runtime</strong><span>${runtime}</span></div>
        `;

        if (meta.case_results) {
            meta.case_results.forEach(r => {
                if (!r.solved) {
                    if (!r.main_failure_reason || r.main_failure_reason === 'N/A') {
                        if (r.attempts >= (meta.max_attempts || 10) && r.first_solved_attempt === null) {
                            r.main_failure_reason = 'max_attempts_exhausted';
                        } else if (r.refusals > 0) {
                            r.main_failure_reason = 'refusal_loop_or_policy_block';
                        } else if (r.solved === false) {
                            r.main_failure_reason = 'not_solved';
                        } else {
                            r.main_failure_reason = 'unknown_failure';
                        }
                    }
                }
            });
            
            if (!meta.failures || meta.failures.length === 0) {
                const unsolved = meta.case_results.filter(r => !r.solved);
                if (unsolved.length > 0) {
                    meta.failures = unsolved.map(r => ({
                        strategy: r.strategy,
                        case_id: r.case_id,
                        main_failure_reason: r.main_failure_reason,
                        observed_failure: `Failed after ${r.attempts || 0} attempts.`,
                        recommended_controller_fix: "Review attempt trajectory and adjust strategy."
                    }));
                }
            }

            calculateAggregates(meta.case_results, meta);
            renderCaseResults(meta.case_results);
        } else {
            document.getElementById('agg-metrics-grid').innerHTML = '<div style="grid-column: span 4;">Metrics not available (case_results.json missing).</div>';
            document.getElementById('taxonomy-summary').innerHTML = '';
            document.getElementById('case-results-content').innerHTML = '<div>Case results data not available.</div>';
        }

        if (meta.failures && meta.failures.length > 0) {
            renderFailures(meta.failures);
        } else {
            document.getElementById('failures-content').innerHTML = '<div>No failure backlog found (or eval had 100% success).</div>';
        }

        const activeTabElement = document.querySelector('.tab.active');
        if (activeTabElement) {
            const tabId = activeTabElement.getAttribute('onclick').match(/'([^']+)'/)[1];
            if (tabId === 'report' || tabId === 'case-results' || tabId === 'failures' || tabId === 'trajectory') {
                loadTabContent(evalId, tabId);
            }
        }
    } catch (e) {
        console.error(e);
    }
}

function calculateAggregates(cases, meta) {
    if (meta.eval_type === 'Mixed Strategy Eval') {
        document.getElementById('agg-metrics-title').innerText = 'Aggregated Metrics by Strategy';
    } else {
        document.getElementById('agg-metrics-title').innerText = 'Aggregated Metrics';
    }

    const autoRuns = cases; // Compute over all available in the case_results if mixed, or filter if requested. Let's just aggregate what we have.
    if (autoRuns.length === 0) {
        document.getElementById('agg-metrics-grid').innerHTML = '<div style="grid-column: span 4;">No strategy data found.</div>';
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
    const solvedRate = count > 0 ? ((solved / count) * 100).toFixed(1) + '%' : 'N/A';
    const avgAttempts = count > 0 ? (totalAttempts / count).toFixed(1) : 'N/A';
    const dupRate = count > 0 ? ((totalDupRate / count) * 100).toFixed(1) + '%' : 'N/A';

    // Calculate Success@K metrics
    let successAt1 = 0, successAt3 = 0, successAt5 = 0, successAt6 = 0;
    autoRuns.forEach(r => {
        if (r.success_at_1) successAt1++;
        if (r.success_at_3) successAt3++;
        if (r.success_at_5) successAt5++;
        if (r.success_at_6) successAt6++;
    });

    document.getElementById('agg-metrics-grid').innerHTML = `
        <div><strong>Solved Rate</strong><span style="color:#4CAF50">${solvedRate}</span></div>
        <div><strong>Total Runs</strong><span>${count}</span></div>
        <div><strong>Avg Attempts</strong><span>${avgAttempts}</span></div>
        <div><strong>Duplicate Rate</strong><span>${dupRate}</span></div>
        <div><strong>Success@1</strong><span>${successAt1}/${count}</span></div>
        <div><strong>Success@3</strong><span>${successAt3}/${count}</span></div>
        <div><strong>Success@5</strong><span>${successAt5}/${count}</span></div>
        <div><strong>Success@6</strong><span>${successAt6}/${count}</span></div>
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

    let readableSummary = `<p>This eval ran the <strong>${meta.strategies ? meta.strategies.join(', ') : 'unknown'}</strong> strategy on ${count} cases. `;
    readableSummary += `The agent solved ${solved}/${count} cases overall, with ${successAt1}/${count} solved on the first attempt and ${successAt3}/${count} solved within 3 attempts. `;
    if (successAt1 < successAt3) {
        readableSummary += `The gap between Success@1 and Success@3 suggests the capability exists, but first-shot reliability is weak. `;
    } else if (successAt1 > 0 && successAt1 === successAt3) {
        readableSummary += `First-shot reliability matches early-retry reliability. `;
    } else if (solved === 0) {
        readableSummary += `The agent failed to solve any cases. `;
    }
    const sortedTax = Object.entries(taxonomy).sort((a,b) => b[1]-a[1]);
    if (sortedTax.length > 0) {
        readableSummary += `The remaining failures are concentrated under <strong>${sortedTax[0][0]}</strong>. `;
    }
    readableSummary += `Recommended next action: inspect failed cases and adjust strategy.</p>`;
    
    const summaryEl = document.getElementById('readable-summary');
    if (summaryEl) summaryEl.innerHTML = readableSummary;
}

function renderCaseResults(cases) {
    if (!cases || cases.length === 0) {
        document.getElementById('case-results-content').innerHTML = '<div>No case results.</div>';
        return;
    }

    let html = '<table><tr><th>Strategy</th><th>Case</th><th>Solved</th><th>Attempts</th><th>Success@1</th><th>Success@3</th><th>Refusals</th><th>Duplicates</th><th>Failure Reason</th><th>Run ID</th></tr>';
    cases.forEach(r => {
        const solvedStr = r.solved ? '<span style="color:#4CAF50">YES</span>' : '<span style="color:#f44336">NO</span>';
        const attempts = r.attempts !== undefined ? r.attempts : 'N/A';
        const s1 = (r.first_solved_attempt === 1) ? '<span style="color:#4CAF50">YES</span>' : '<span style="color:#f44336">NO</span>';
        const s3 = (r.first_solved_attempt !== undefined && r.first_solved_attempt !== null && r.first_solved_attempt <= 3) ? '<span style="color:#4CAF50">YES</span>' : '<span style="color:#f44336">NO</span>';
        const refusals = (r.refusals !== undefined && r.refusals !== null) ? r.refusals : '-';
        const duplicates = (r.duplicates !== undefined && r.duplicates !== null) ? r.duplicates : '-';
        const failure = r.main_failure_reason || 'N/A';
        const runId = r.run_id ? r.run_id.substring(0, 8) + '...' : 'N/A';

        html += `<tr>
            <td>${r.strategy}</td>
            <td>${r.case_id}</td>
            <td>${solvedStr}</td>
            <td>${attempts}</td>
            <td>${s1}</td>
            <td>${s3}</td>
            <td>${refusals}</td>
            <td>${duplicates}</td>
            <td>${failure}</td>
            <td>${runId}</td>
        </tr>`;
    });
    html += '</table>';
    document.getElementById('case-results-content').innerHTML = html;
}

function renderFailures(failures) {
    if (!failures || failures.length === 0) {
        document.getElementById('failures-content').innerHTML = '<div>No failure cases.</div>';
        return;
    }

    let html = '<table><tr><th>Strategy</th><th>Case</th><th>Wizard Opening Prompt</th><th>Failure Reason</th><th>Observed Failure</th><th>Recommendation</th></tr>';
    failures.forEach(f => {
        const wizard = (f.wizard_opening_prompt && f.wizard_opening_prompt !== '-') ? f.wizard_opening_prompt.replace(/</g, "&lt;").replace(/>/g, "&gt;") : '-';
        html += `<tr>
            <td>${f.strategy}</td>
            <td>${f.case_id}</td>
            <td><pre style="margin:0;max-height:100px;overflow:auto;font-size:0.85em;background:transparent;border:none;">${wizard}</pre></td>
            <td>${f.main_failure_reason}</td>
            <td>${f.observed_failure}</td>
            <td>${f.recommended_controller_fix}</td>
        </tr>`;
    });
    html += '</table>';
    document.getElementById('failures-content').innerHTML = html;
}

function renderTrajectory(traj) {
    if (!traj || traj.length === 0) {
        document.getElementById('trajectory-content').innerHTML = '<div>No transcript available.</div>';
        return;
    }
    let html = '<table><tr><th>Level</th><th>Attempt</th><th>Prompt</th><th>Solved</th><th>Run ID</th></tr>';
    traj.forEach(t => {
        const solvedStr = t.solved ? '<span style="color:#4CAF50">YES</span>' : '<span style="color:#f44336">NO</span>';
        const promptRaw = t.prompt || t.selected_prompt || '';
        const safePrompt = promptRaw.replace(/</g, "&lt;").replace(/>/g, "&gt;");
        
        let promptContent = '';
        if (t.attempt === 1 && t.wizard_opening_prompt && t.wizard_opening_prompt !== '-') {
             const safeWizard = t.wizard_opening_prompt.replace(/</g, "&lt;").replace(/>/g, "&gt;");
             promptContent += `<div style="margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px dashed #555;">
                 <strong style="color: #9cdcfe;">Wizard Opening Prompt:</strong><br/>
                 <pre style="margin:0;white-space:pre-wrap;font-size:0.9em;background:transparent;border:none;">${safeWizard}</pre>
             </div>`;
        }
        promptContent += `<strong style="color: #ce9178;">Attack Prompt:</strong><br/>
             <pre style="margin:0;max-height:150px;overflow:auto;white-space:pre-wrap;font-size:0.9em;background:transparent;border:none;padding:0;">${safePrompt}</pre>`;

        html += `<tr>
            <td>${t.level_id || t.current_level || 'Unknown'}</td>
            <td>${t.attempt || 'N/A'}</td>
            <td>${promptContent}</td>
            <td>${solvedStr}</td>
            <td>${t.run_id || 'N/A'}</td>
        </tr>`;
    });
    html += '</table>';
    document.getElementById('trajectory-content').innerHTML = html;
}

async function loadTabContent(evalId, artifact) {
    if (artifact === 'summary') return;

    let elId = artifact === 'eval_report' ? 'report-content' : `${artifact}-content`;
    if (artifact === 'report') {
        artifact = 'eval_report';
        elId = 'report-content';
    } else if (artifact === 'case-results') {
        artifact = 'case_results';
        elId = 'case-results-content';
    } else if (artifact === 'trajectory') {
        elId = 'trajectory-content';
    }

    const el = document.getElementById(elId);
    if (!el) return;

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
        } else if (artifact === 'trajectory') {
            const json = await res.json();
            renderTrajectory(json);
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

function loadSidebarState() {
    const isCollapsed = localStorage.getItem('wizardLabEvalsSidebarCollapsed') === 'true';
    setSidebarCollapsed(isCollapsed);
}

function toggleSidebar() {
    const isCollapsed = document.body.classList.contains('sidebar-collapsed');
    setSidebarCollapsed(!isCollapsed);
}

function setSidebarCollapsed(collapsed) {
    if (collapsed) {
        document.body.classList.add('sidebar-collapsed');
        localStorage.setItem('wizardLabEvalsSidebarCollapsed', 'true');
        const btn = document.getElementById('sidebar-toggle');
        if(btn) btn.innerText = 'Show Sidebar';
    } else {
        document.body.classList.remove('sidebar-collapsed');
        localStorage.setItem('wizardLabEvalsSidebarCollapsed', 'false');
        const btn = document.getElementById('sidebar-toggle');
        if(btn) btn.innerText = 'Hide Sidebar';
    }
}

// Init
loadSidebarState();
fetchEvals();

// Removed planner status and Gemini run button logic
