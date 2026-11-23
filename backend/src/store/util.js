const pad = (n) => String(n).padStart(2, '0');
const toDate = (v) => (v instanceof Date ? v : new Date(v));

module.exports = { pad, toDate };
