const WebSocket = require('ws');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG = {
  PORT: 3000,
  WS_PORT: 4000,
  PASSWORD: 'admin123',
  SESSION_TIMEOUT: 30 * 60 * 1000,
};

const operatorSessions = new Map();
const agents = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

const httpServer = http.createServer((req, res) => {
  const frontendDir = path.join(__dirname, '..', 'Frontend', 'public');
  let filePath = path.join(frontendDir, req.url === '/' ? 'index.html' : req.url);
  const ext = path.extname(filePath);
  const mimeTypes = {
    '.html': 'text/html',
    '.css':  'text/css',
    '.js':   'text/javascript',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
  };
  const contentType = mimeTypes[ext] || 'text/plain';
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
});

httpServer.listen(CONFIG.PORT, () => {
  console.log(`[HTTP] Frontend disponível em http://localhost:${CONFIG.PORT}`);
});

const wss = new WebSocket.Server({ port: CONFIG.WS_PORT }, () => {
  console.log(`[WS] WebSocket Server rodando na porta ${CONFIG.WS_PORT}`);
});

wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`[WS] Nova conexão de ${clientIp}`);
  ws.isAuthenticated = false;
  ws.clientType = null;
  ws.agentId = null;
  ws.operatorToken = null;

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      ws.send(JSON.stringify({ type: 'error', message: 'JSON inválido' }));
      return;
    }
    handleMessage(ws, msg);
  });

  ws.on('close', () => {
    if (ws.clientType === 'agent' && ws.agentId) {
      agents.delete(ws.agentId);
      console.log(`[AGENT] Agente desconectado: ${ws.agentId}`);
      broadcastToOperators({ type: 'agent_disconnected', agentId: ws.agentId });
    }
    if (ws.clientType === 'operator' && ws.operatorToken) {
      operatorSessions.delete(ws.operatorToken);
      console.log(`[OPERATOR] Operador desconectado`);
    }
  });

  ws.on('error', (err) => {
    console.error(`[WS] Erro: ${err.message}`);
  });
});

function handleMessage(ws, msg) {
  if (msg.type === 'operator_auth') {
    if (msg.password === CONFIG.PASSWORD) {
      const token = generateToken();
      ws.isAuthenticated = true;
      ws.clientType = 'operator';
      ws.operatorToken = token;
      operatorSessions.set(token, { ws, lastActive: Date.now() });
      const agentList = [];
      agents.forEach((agent, id) => {
        agentList.push({ agentId: id, info: agent.info, connectedAt: agent.connectedAt });
      });
      ws.send(JSON.stringify({
        type: 'auth_success',
        token,
        agents: agentList,
      }));
      console.log(`[OPERATOR] Operador autenticado`);
      return;
    }
    ws.send(JSON.stringify({ type: 'auth_failed', message: 'Senha incorreta' }));
    return;
  }

  if (msg.type === 'agent_register') {
    const agentId = crypto.randomBytes(8).toString('hex');
    ws.isAuthenticated = true;
    ws.clientType = 'agent';
    ws.agentId = agentId;
    agents.set(agentId, {
      ws,
      info: msg.info || {},
      connectedAt: new Date().toISOString(),
    });
    ws.send(JSON.stringify({ type: 'registered', agentId }));
    console.log(`[AGENT] Agente registrado: ${agentId} | ${JSON.stringify(msg.info)}`);
    broadcastToOperators({
      type: 'agent_connected',
      agentId,
      info: msg.info || {},
      connectedAt: new Date().toISOString(),
    });
    return;
  }

  if (!ws.isAuthenticated) {
    ws.send(JSON.stringify({ type: 'error', message: 'Não autenticado' }));
    return;
  }

  if (msg.type === 'command' && ws.clientType === 'operator') {
    const agent = agents.get(msg.agentId);
    if (!agent) {
      ws.send(JSON.stringify({ type: 'error', message: 'Agente não encontrado' }));
      return;
    }
    agent.ws.send(JSON.stringify({
      type: 'command',
      commandId: msg.commandId,
      command: msg.command,
      args: msg.args || [],
    }));
    return;
  }

  if (msg.type === 'command_result' && ws.clientType === 'agent') {
    broadcastToOperators({
      type: 'command_result',
      agentId: ws.agentId,
      commandId: msg.commandId,
      output: msg.output,
      error: msg.error || null,
    });
    return;
  }

  if (msg.type === 'data' && ws.clientType === 'agent') {
    broadcastToOperators({
      type: 'data',
      agentId: ws.agentId,
      dataType: msg.dataType,
      payload: msg.payload,
    });
    return;
  }

  ws.send(JSON.stringify({ type: 'error', message: 'Tipo de mensagem desconhecido' }));
}

function broadcastToOperators(msg) {
  const data = JSON.stringify(msg);
  operatorSessions.forEach(({ ws }) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });
}

setInterval(() => {
  const now = Date.now();
  operatorSessions.forEach((session, token) => {
    if (now - session.lastActive > CONFIG.SESSION_TIMEOUT) {
      session.ws.close();
      operatorSessions.delete(token);
      console.log(`[SESSION] Sessão expirada removida`);
    }
  });
}, 60 * 1000);

console.log('[SERVER] Remote Administration Tool - Servidor iniciado');
console.log(`[SERVER] Dashboard: http://localhost:${CONFIG.PORT}`);
console.log(`[SERVER] WebSocket: ws://localhost:${CONFIG.WS_PORT}`);
