// Minimal safe MCP stdio server. No fs, no child_process, no eval.
import readline from 'node:readline';
const rl = readline.createInterface({ input: process.stdin });
function send(o){ process.stdout.write(JSON.stringify(o) + "\n"); }
rl.on('line', (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  const id = m.id;
  if (m.method === 'initialize') {
    return send({jsonrpc:"2.0", id, result:{protocolVersion:"2024-11-05",
      capabilities:{tools:{}}, serverInfo:{name:"clean-server",version:"1.0.0"}}});
  }
  if (m.method === 'tools/list') {
    return send({jsonrpc:"2.0", id, result:{tools:[
      {name:"ping", description:"returns a fixed string",
       inputSchema:{type:"object",properties:{}}}]}});
  }
  if (m.method === 'tools/call' && m.params && m.params.name === 'ping') {
    return send({jsonrpc:"2.0", id, result:{content:[{type:"text",text:"pong"}]}});
  }
  if (m.method && m.method.startsWith('notifications/')) return;
  send({jsonrpc:"2.0", id, error:{code:-32601, message:"Method not found"}});
});
