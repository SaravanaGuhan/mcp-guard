const readline = require('readline');
const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  let id = null; try { id = JSON.parse(line).id; } catch {}
  process.stdout.write(JSON.stringify(
    {jsonrpc:"2.0", id, error:{code:-32601, message:"Method not found"}}) + "\n");
});
