const fs = require('fs');
const path = require('path');

const usersFile = path.join(__dirname, '../users.json');

if (!fs.existsSync(usersFile)) {
    console.error("users.json not found!");
    process.exit(1);
}

const users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
let count = 0;

Object.keys(users).forEach(email => {
    if (users[email].is2faSetup) {
        users[email].is2faSetup = false;
        count++;
    }
});

fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
console.log(`✅ 2FA disabled for ${count} users.`);
