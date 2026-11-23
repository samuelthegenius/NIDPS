/** Sets KEY=value lines in .env text, keeping every other line as it was. */
function setEnvValues(text, values) {
  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const pending = new Map(Object.entries(values));
  const out = lines.map((line) => {
    const key = line.split('=')[0].trim();
    if (!line.trim().startsWith('#') && pending.has(key)) {
      const value = pending.get(key);
      pending.delete(key);
      return `${key}=${value}`;
    }
    return line;
  });
  for (const [key, value] of pending) out.push(`${key}=${value}`);
  return `${out.join('\n')}\n`;
}

module.exports = { setEnvValues };
