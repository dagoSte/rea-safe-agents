const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');

async function main() {
  const status = fs.readFileSync('/proc/self/status', 'utf8');
  function denied(path) {
    try {
      fs.writeFileSync(path, 'isolation probe', { flag: 'wx' });
      fs.unlinkSync(path);
      return false;
    } catch (error) {
      return ['EROFS', 'EACCES', 'EPERM'].includes(error.code);
    }
  }
  const outboundDenied = await new Promise((resolve) => {
    const socket = net.connect({host: '1.1.1.1', port: 443});
    socket.setTimeout(1500);
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => { socket.destroy(); resolve(true); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
  const homeFile = '/home/node/.rea-isolation-probe';
  fs.writeFileSync(homeFile, 'temporary');
  fs.unlinkSync(homeFile);
  function read(path) {
    try { return fs.readFileSync(path, 'utf8').trim(); }
    catch { return null; }
  }
  const v2 = fs.existsSync('/sys/fs/cgroup/cgroup.controllers');
  const memory = Number(read(v2 ? '/sys/fs/cgroup/memory.max' : '/sys/fs/cgroup/memory/memory.limit_in_bytes'));
  const swap = Number(read(v2 ? '/sys/fs/cgroup/memory.swap.max' : '/sys/fs/cgroup/memory/memory.memsw.limit_in_bytes'));
  const pids = Number(read(v2 ? '/sys/fs/cgroup/pids.max' : '/sys/fs/cgroup/pids/pids.max'));
  const cpu = v2 ? (read('/sys/fs/cgroup/cpu.max') || '').split(' ').map(Number)
    : [Number(read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us')), Number(read('/sys/fs/cgroup/cpu/cpu.cfs_period_us'))];
  const result = {
    nonRoot: process.getuid() === 1000,
    noNewPrivileges: /^NoNewPrivs:\s+1$/m.test(status),
    noEffectiveCapabilities: /^CapEff:\s+0+$/m.test(status),
    seccompFilterActive: /^Seccomp:\s+2$/m.test(status),
    noNonLoopbackInterfaces: Object.keys(os.networkInterfaces()).every((name) => name === 'lo'),
    rootWriteDenied: denied('/.rea-isolation-probe'),
    inputWriteDenied: denied('/input/.rea-isolation-probe'),
    noDockerSocket: !fs.existsSync('/var/run/docker.sock'),
    outboundConnectionDenied: outboundDenied,
    temporaryHomeWritable: true,
    memoryLimitEnforced: memory > 0 && memory <= 2 * 1024 ** 3,
    swapLimitEnforced: v2 ? read('/sys/fs/cgroup/memory.swap.max') === '0' : swap > 0 && swap <= 2 * 1024 ** 3,
    processLimitEnforced: pids > 0 && pids <= 128,
    cpuLimitEnforced: cpu[0] > 0 && cpu[1] > 0 && cpu[0] / cpu[1] <= 2,
  };
  console.log(JSON.stringify(result));
  if (Object.values(result).some((value) => value !== true)) process.exitCode = 1;
}
main().catch((error) => { console.error(error.message); process.exitCode = 1; });
