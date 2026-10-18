// Usage: node createuser.js <username> <password>   (adds the user, or resets their password)
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [u, pw] = process.argv.slice(2);
if (!u || !pw || pw.length < 10) { console.log('Usage: node createuser.js <username> <password of 10+ characters>'); process.exit(1); }
const file = path.join(__dirname, 'data', 'users.json');
fs.mkdirSync(path.dirname(file), { recursive: true });
const users = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
const salt = crypto.randomBytes(16).toString('hex');
const rec = { username: u.toLowerCase(), salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
const i = users.findIndex(x => x.username === rec.username);
i >= 0 ? users[i] = rec : users.push(rec);
fs.writeFileSync(file, JSON.stringify(users, null, 2), { mode: 0o600 });
console.log(`${i >= 0 ? 'Updated' : 'Added'} user "${rec.username}". Restart not needed.`);
