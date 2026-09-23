import re

def update_index_html():
    with open('index.html', 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Update Hero button
    content = content.replace(
        '<span id="toggleBtnLabel">Pause live scan</span>',
        '<span id="toggleBtnLabel">Run Live Assessment</span>'
    )

    # 2. Update Hero stat grid
    content = content.replace(
        '<div class="stat"><div class="n" id="statEndpoints">128</div><div class="l">Endpoints monitored</div></div>',
        '<div class="stat"><div class="n" id="statEndpoints">0</div><div class="l">Endpoints monitored</div></div>'
    )

    # 3. Update target picker default label
    content = content.replace(
        '<strong id="targetActiveLabel">Demo fleet (128 simulated endpoints)</strong>\n        <span class="sim-note" id="simNote">Simulated &mdash; no real requests sent</span>',
        '<strong id="targetActiveLabel">http://127.0.0.1:8000</strong>\n        <span class="sim-note" id="simNote" style="background:var(--risk-soft);color:var(--risk);">Live Assessment Mode</span>'
    )
    content = content.replace(
        'placeholder="example.com"',
        'placeholder="http://127.0.0.1:8000"'
    )

    # 4. Insert CSS
    css_to_insert = """
  /* ---------- Terminal Console ---------- */
  .terminal-wrap {
    background: #111418;
    color: #e4e7eb;
    border-radius: var(--radius-m);
    padding: 16px;
    font-family: var(--font-mono);
    font-size: 13px;
    height: 400px;
    overflow-y: auto;
    border: 1px solid var(--ink);
    margin-top: 24px;
    line-height: 1.6;
  }
  .terminal-wrap .t-time { color: #5b6470; margin-right: 8px; }
  .terminal-wrap .t-agent { color: var(--accent); font-weight: 600; margin-right: 8px; }
  .terminal-wrap .t-event { color: #9aa2ac; margin-right: 8px; }
  .terminal-wrap .t-detail { color: #e4e7eb; }
  .terminal-wrap .t-error { color: var(--risk); }

  /* ---------- Phase Timeline ---------- */
  .phase-timeline {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 24px;
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: var(--radius-m);
    padding: 20px 24px;
    position: relative;
  }
  .phase-step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    z-index: 2;
    position: relative;
    flex: 1;
    text-align: center;
  }
  .phase-icon {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--panel-alt);
    border: 2px solid var(--line-strong);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--ink-soft);
    font-size: 14px;
    font-weight: 600;
    transition: all 0.3s ease;
  }
  .phase-step.active .phase-icon {
    border-color: var(--accent);
    background: var(--accent-soft);
    color: var(--accent);
    box-shadow: 0 0 0 4px rgba(58, 110, 165, 0.15);
  }
  .phase-step.completed .phase-icon {
    border-color: var(--ok);
    background: var(--ok);
    color: #fff;
  }
  .phase-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--ink-soft);
  }
  .phase-step.active .phase-label { color: var(--ink); }
  .phase-step.completed .phase-label { color: var(--ink); }
  
  .phase-track {
    position: absolute;
    top: 35px;
    left: 40px;
    right: 40px;
    height: 2px;
    background: var(--line);
    z-index: 1;
  }
  .phase-progress {
    height: 100%;
    background: var(--accent);
    width: 0%;
    transition: width 0.5s ease;
  }
  /* ---------- Animations ---------- */
"""
    content = content.replace('  /* ---------- Animations ---------- */\n', css_to_insert)

    # 5. Insert HTML Console
    html_to_insert = """      </div>

      <div id="liveConsole" style="display: none; margin-top: 40px; padding-top: 40px; border-top: 1px solid var(--line);">
        <div class="section-head">
          <div>
            <h2>Live Execution Console</h2>
            <p>Real-time telemetry and analysis from the PANDA agents.</p>
          </div>
        </div>

        <div class="phase-timeline">
          <div class="phase-track"><div class="phase-progress" id="phaseProgress"></div></div>
          <div class="phase-step" id="phase-recon"><div class="phase-icon">1</div><div class="phase-label">Recon</div></div>
          <div class="phase-step" id="phase-understanding"><div class="phase-icon">2</div><div class="phase-label">Understanding</div></div>
          <div class="phase-step" id="phase-threat_modeling"><div class="phase-icon">3</div><div class="phase-label">Threat Modeling</div></div>
          <div class="phase-step" id="phase-test_planning"><div class="phase-icon">4</div><div class="phase-label">Planning</div></div>
          <div class="phase-step" id="phase-execution"><div class="phase-icon">5</div><div class="phase-label">Execution</div></div>
          <div class="phase-step" id="phase-reporting"><div class="phase-icon">6</div><div class="phase-label">Reporting</div></div>
        </div>

        <div class="terminal-wrap" id="terminalLog">
          <div class="t-detail">PANDA agent standing by. Ready to execute assessment.</div>
        </div>
      </div>

    </div>
  </section>"""
    
    # Replace the end of the workflow section
    content = content.replace('      </div>\n    </div>\n  </section>', html_to_insert)

    # 6. Replace Script completely
    script_start = content.find('<script>')
    if script_start != -1:
        content = content[:script_start] + """<script>
(function(){
  "use strict";

  var targetUrl = "http://127.0.0.1:8000";
  var allowWrite = false;
  var ws = null;
  var isRunning = false;
  
  var toggleBtn = document.getElementById('toggleBtn');
  var toggleBtnLabel = document.getElementById('toggleBtnLabel');
  var livePill = document.getElementById('livePill');
  var livePillLabel = document.getElementById('livePillLabel');
  var terminalLog = document.getElementById('terminalLog');
  var liveConsole = document.getElementById('liveConsole');
  var phaseProgress = document.getElementById('phaseProgress');
  
  var findingsList = document.getElementById('findingsList');
  var findingsEmpty = document.getElementById('findingsEmpty');
  var statFindings = document.getElementById('statFindings');
  var statChecks = document.getElementById('statChecks');
  var statEndpoints = document.getElementById('statEndpoints');
  var apiLog = document.getElementById('apiLog');
  
  var checksCount = 0;

  var targetInput = document.getElementById('targetInput');
  var targetForm = document.getElementById('targetForm');
  var targetActiveLabel = document.getElementById('targetActiveLabel');

  targetForm.addEventListener('submit', function(e) {
    e.preventDefault();
    if(targetInput.value) {
       targetUrl = targetInput.value;
       if (!/^https?:\\/\\//i.test(targetUrl)) targetUrl = 'http://' + targetUrl;
       targetActiveLabel.textContent = targetUrl;
    }
  });

  function appendTerminal(agent, event, detail, isError) {
    var line = document.createElement('div');
    var d = new Date();
    var time = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
    
    var html = '<span class="t-time">' + time + '</span>';
    html += '<span class="t-agent">[' + agent + ']</span>';
    if(event) html += '<span class="t-event">' + event + '</span>';
    
    var detailClass = isError ? 't-error' : 't-detail';
    html += '<span class="' + detailClass + '">' + detail + '</span>';
    
    line.innerHTML = html;
    terminalLog.appendChild(line);
    terminalLog.scrollTop = terminalLog.scrollHeight;
  }

  function setPhase(phaseId, progress) {
    var phases = ['recon', 'understanding', 'threat_modeling', 'test_planning', 'execution', 'reporting'];
    var activeIdx = phases.indexOf(phaseId);
    if(activeIdx === -1) return;
    
    phases.forEach(function(p, i) {
       var el = document.getElementById('phase-' + p);
       if(!el) return;
       if(i < activeIdx) {
           el.classList.add('completed');
           el.classList.remove('active');
       } else if(i === activeIdx) {
           el.classList.add('active');
           el.classList.remove('completed');
       } else {
           el.classList.remove('active');
           el.classList.remove('completed');
       }
    });
    
    if(progress !== undefined && progress !== null) {
       phaseProgress.style.width = progress + '%';
    }
  }

  function renderFindings(findings) {
      if(!findings || !findings.length) return;
      findingsEmpty.style.display = 'none';
      statFindings.textContent = findings.length;
      
      var SEV_LABEL = { 'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low', 'INFO': 'Info' };
      findingsList.innerHTML = '';
      
      findings.forEach(function(f) {
        var el = document.createElement('div');
        var sevClass = f.severity.toLowerCase();
        el.className = 'finding sev-' + sevClass;
        el.innerHTML =
          '<span class="sev-chip sev-' + sevClass + '">' + (SEV_LABEL[f.severity] || f.severity) + '</span>' +
          '<div class="finding-main"><div class="title">' + f.title + '</div>' +
            '<div class="meta">' + f.owasp_category + ' &middot; ' + f.id + '</div></div>';
        findingsList.appendChild(el);
      });
  }

  function logApiCall(method, path, status, ms) {
    checksCount++;
    statChecks.textContent = checksCount;
    var statusClass = status >= 400 ? 's4' : (status >= 200 && status < 300 ? 's2' : '');
    var line = document.createElement('div');
    var d = new Date();
    var time = String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
    line.innerHTML = time + '&nbsp;&nbsp;<span class="m">' + String(method).padEnd(5) + '</span>' + path + '&nbsp;&nbsp;<span class="' + statusClass + '">' + status + '</span>&nbsp;&nbsp;' + Math.round(ms) + 'ms';
    apiLog.appendChild(line);
    while(apiLog.children.length > 50){ apiLog.removeChild(apiLog.firstChild); }
    apiLog.scrollTop = apiLog.scrollHeight;
  }

  function connectAndRun() {
    if(isRunning) return;
    
    liveConsole.style.display = 'block';
    appendTerminal('system', 'init', 'Connecting to PANDA backend WebSocket...');
    
    ws = new WebSocket('ws://' + window.location.host + '/ws/run');
    
    ws.onopen = function() {
      isRunning = true;
      toggleBtnLabel.textContent = 'Assessment Running...';
      toggleBtn.disabled = true;
      livePill.classList.remove('paused');
      livePillLabel.textContent = 'Live';
      
      // Send config
      ws.send(JSON.stringify({ target_url: targetUrl, allow_write: allowWrite }));
      appendTerminal('system', 'connected', 'Triggered PANDA pipeline against ' + targetUrl);
    };
    
    ws.onmessage = function(e) {
      try {
        var msg = JSON.parse(e.data);
        
        // Progress / Phase updates
        if(msg.type === 'phase_start' || msg.type === 'phase_complete') {
            if(msg.phase) setPhase(msg.phase, msg.progress);
        } else if (msg.progress !== undefined) {
            phaseProgress.style.width = msg.progress + '%';
        }
        
        // Render findings
        if(msg.findings && msg.findings.length > 0) {
            renderFindings(msg.findings);
        }
        
        // Render API Calls
        if(msg.agent === 'executor' && msg.action === 'called tool') {
             // Try to parse out method, path, status from detail string like "GET /api/v1/users (anonymous) -> 200"
             var m = msg.detail.match(/^([A-Z]+)\\s+(.*?)\\s+\\(.*?\\)\\s*->\\s*(\\d+)/);
             if(m) {
                 logApiCall(m[1], m[2], m[3], 50 + Math.random()*100);
             }
        }
        
        var isErr = msg.type === 'error';
        appendTerminal(msg.agent, msg.action, msg.detail || '', isErr);
        
      } catch(err) {
        console.error("Error parsing WS message", err);
      }
    };
    
    ws.onclose = function() {
      isRunning = false;
      toggleBtnLabel.textContent = 'Run Live Assessment';
      toggleBtn.disabled = false;
      livePill.classList.add('paused');
      livePillLabel.textContent = 'Paused';
      appendTerminal('system', 'disconnected', 'Pipeline connection closed.');
    };
    
    ws.onerror = function(err) {
      appendTerminal('system', 'error', 'WebSocket error', true);
    };
  }

  toggleBtn.addEventListener('click', function(){
      if(!isRunning) {
          checksCount = 0;
          statChecks.textContent = '0';
          apiLog.innerHTML = '';
          terminalLog.innerHTML = '';
          connectAndRun();
      }
  });

})();
</script>
</body>
</html>
"""

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("Done rewriting index.html")

update_index_html()
