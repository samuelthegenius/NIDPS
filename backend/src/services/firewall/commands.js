/**
 * Builds iptables argument vectors (never shell strings) for the NIDPS chain.
 *
 * NIDPS keeps all of its rules in its own chain called "NIDPS", reached by one
 * jump rule at the top of INPUT (host mode: protect this machine) or FORWARD
 * (gateway mode: protect the network routed through this machine). Flushing or
 * resetting NIDPS therefore never touches anyone else's firewall rules.
 */
const net = require('net');

const CHAIN = 'NIDPS';

function buildCommands({ mode = 'host', platform = process.platform, wslDistro = 'Ubuntu-24.04', isRoot = false }) {
  const parent = mode === 'gateway' ? 'FORWARD' : 'INPUT';
  const tool = (family) => (family === 'ipv6' ? 'ip6tables' : 'iptables');

  function prefix(family) {
    if (platform === 'win32') return ['wsl', '-d', wslDistro, '-u', 'root', tool(family)];
    return isRoot ? [tool(family)] : ['sudo', '-n', tool(family)];
  }
  const familyOf = (ip) => (net.isIPv6(ip) ? 'ipv6' : 'ipv4');
  const rule = (ip) => ['-s', ip, '-j', 'DROP'];

  return {
    chain: CHAIN,
    parent,
    setup: (family) => ({
      create: [...prefix(family), '-N', CHAIN],
      checkJump: [...prefix(family), '-C', parent, '-j', CHAIN],
      insertJump: [...prefix(family), '-I', parent, '1', '-j', CHAIN],
    }),
    check: (ip) => [...prefix(familyOf(ip)), '-C', CHAIN, ...rule(ip)],
    block: (ip) => [...prefix(familyOf(ip)), '-I', CHAIN, '1', ...rule(ip)],
    unblock: (ip) => [...prefix(familyOf(ip)), '-D', CHAIN, ...rule(ip)],
    flush: (family) => [...prefix(family), '-F', CHAIN],
  };
}

module.exports = { buildCommands, CHAIN };
