// Deliberately vulnerable MCP server for scanner testing.
// It contains exactly THREE planted vulnerabilities, listed below. Anything a
// scanner reports beyond these three is a false positive.
//   1. child_process.exec on an unsanitised tool argument   (command injection)
//   2. fs.readFileSync on an unsanitised resource path      (path traversal)
//   3. a hardcoded credential in source                     (secret)
import readline from 'node:readline';
import { exec } from 'node:child_process';
import fs from 'node:fs';

// PLANTED VULN 3: hardcoded credential
const API_KEY = "MCPGUARD_FAKE_SECRET_4f3a9c1e8b7d2a6f5c0e9b4a7d1f3e8c";

const rl = readline.createInterface({ input: process.stdin });
function send(o) { process.stdout.write(JSON.stringify(o) + "\n"); }
function fail(id, message) {
  send({ jsonrpc: "2.0", id, error: { code: -32603, message } });
}

rl.on('line', (line) => {
  let m;
  try { m = JSON.parse(line); } catch { return; }   // not a crash: ignore bad frames
  const id = m.id;
  try {
    if (m.method === 'initialize') {
      return send({ jsonrpc: "2.0", id, result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {}, resources: {} },
        serverInfo: { name: "vulnerable-server", version: "1.0.0" } } });
    }
    if (m.method === 'tools/list') {
      return send({ jsonrpc: "2.0", id, result: { tools: [
        { name: "run", description: "run a shell command",
          inputSchema: { type: "object", properties: { cmd: { type: "string" } },
                         required: ["cmd"] } }] } });
    }
    // PLANTED VULN 1: argument passed straight to child_process.exec
    if (m.method === 'tools/call' && m.params && m.params.name === 'run') {
      exec(m.params.arguments.cmd, (e, stdout, stderr) => {
        send({ jsonrpc: "2.0", id, result: {
          content: [{ type: "text", text: String(stdout || stderr || "") }] } });
      });
      return;
    }
    // PLANTED VULN 2: unsanitised path into fs.readFileSync
    if (m.method === 'resources/read') {
      const p = m.params.uri.replace('file://', '');
      const data = fs.readFileSync(p, 'utf8');
      return send({ jsonrpc: "2.0", id, result: {
        contents: [{ uri: m.params.uri, text: data }] } });
    }
    if (m.method === 'resources/list') {
      return send({ jsonrpc: "2.0", id, result: { resources: [] } });
    }
    if (m.method && m.method.startsWith('notifications/')) return;
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
  } catch (err) {
    fail(id, String(err && err.message ? err.message : err));
  }
});
