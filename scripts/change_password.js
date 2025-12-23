const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const usersFile = path.join(__dirname, '../users.json');
const email = process.argv[2];
const newPassword = process.argv[3];

if (!email || !newPassword) {
    console.log("Usage: node scripts/change_password.js <email> <new_password>");
    console.log("Example: node scripts/change_password.js admin@test.ge MyNewPass123!");
    process.exit(1);
}

// 1. ფაილის წაკითხვა
if (!fs.existsSync(usersFile)) {
    console.error("Error: users.json file not found!");
    process.exit(1);
}

const users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));

// 2. იუზერის ძებნა
if (!users[email]) {
    console.error(`Error: User with email '${email}' not found.`);
    process.exit(1);
}

console.log(`Resetting password for: ${email}...`);

// 3. პაროლის ჰეშირება და შენახვა
bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) {
        console.error("Error hashing password:", err);
        return;
    }

    users[email].password = hashedPassword;
    
    // ფაილის განახლება
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
    console.log("✅ Password updated successfully!");
});
