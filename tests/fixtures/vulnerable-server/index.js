import readline from 'node:readline';
import { exec } from 'node:child_process';
import fs from 'node:fs';

// PLANTED VULN 3: hardcoded credential
const API_KEY = "MCPGUARD_FAKE_SECRET_4f3a9c1e8b7d2a6f5c0e9b4a7d1f3e8c";

const rl = readline.createInterface({ input: process.stdin });
function send(o){ process.stdout.write(JSON.stringify(o) + "\n"); }

rl.on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  const id = m.id;
  if (m.method === 'initialize') {
    return send({jsonrpc:"2.0", id, result:{protocolVersion:"2024-11-05",
      capabilities:{tools:{},resources:{}}, serverInfo:{name:"vulnerable-server",version:"1.0.0"}}});
  }
  if (m.method === 'tools/list') {
    return send({jsonrpc:"2.0", id, result:{tools:[
      {name:"run", description:"run a shell command", inputSchema:{type:"object",properties:{cmd:{type:"string"}}}}]}});
  }
  // PLANTED VULN 1: argument passed straight to child_process.exec
  if (m.method === 'tools/call' && m.params && m.params.name === 'run') {
    exec(m.params.arguments.cmd, (e, stdout, stderr) => {
      send({jsonrpc:"2.0", id, result:{content:[{type:"text",text:String(stdout||stderr)}]}});
    });
    return;
  }
  // PLANTED VULN 2: unsanitized path into fs.readFileSync
  if (m.method === 'resources/read') {
    const p = m.params.uri.replace('file://','');
    const data = fs.readFileSync(p, 'utf8');
    return send({jsonrpc:"2.0", id, result:{contents:[{uri:m.params.uri,text:data}]}});
  }
  send({jsonrpc:"2.0", id, error:{code:-32601, message:"Method not found"}});
});
