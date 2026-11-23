/**
 * `npm run setup` - first-time setup.
 *   - creates backend/.env from .env.example if it does not exist
 *   - asks for the admin password (hidden) and stores only its scrypt hash
 *   - generates a random SESSION_SECRET if there is none
 * Non-interactive use: NIDPS_ADMIN_PASSWORD=... npm run setup
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');
const { hashPassword } = require('../src/auth/password');
const { setEnvValues } = require('../src/lib/envFile');

const ENV_PATH = path.join(__dirname, '../.env');
const EXAMPLE_PATH = path.join(__dirname, '../.env.example');
const MIN_LENGTH = 10;

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => {
      if (s.startsWith(question)) process.stdout.write(question);
    };
    rl.question(question, (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer);
    });
  });
}

async function main() {
  if (!fs.existsSync(ENV_PATH)) {
    fs.copyFileSync(EXAMPLE_PATH, ENV_PATH);
    console.log('Created backend/.env from .env.example');
  }

  let password = process.env.NIDPS_ADMIN_PASSWORD;
  if (!password) {
    password = await askHidden(`Choose the admin password (min ${MIN_LENGTH} characters): `);
    const again = await askHidden('Repeat the password: ');
    if (password !== again) throw new Error('Passwords do not match.');
  }
  if (password.length < MIN_LENGTH) throw new Error(`Password must be at least ${MIN_LENGTH} characters.`);

  const current = fs.readFileSync(ENV_PATH, 'utf8');
  const hasSecret = /^SESSION_SECRET=.{32,}$/m.test(current);
  const values = { ADMIN_PASSWORD_HASH: hashPassword(password) };
  if (!hasSecret) values.SESSION_SECRET = crypto.randomBytes(32).toString('hex');

  fs.writeFileSync(ENV_PATH, setEnvValues(current, values), { encoding: 'utf8', mode: 0o600 });
  console.log('Saved the admin password hash' + (hasSecret ? '' : ' and a new session secret') + ' to backend/.env');
  console.log('Log in as the ADMIN_USERNAME in .env (default: admin).');
}

main().catch((err) => {
  console.error(`Setup failed: ${err.message}`);
  process.exitCode = 1;
});
