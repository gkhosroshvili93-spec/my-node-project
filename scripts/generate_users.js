const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const usersCount = 30;
const usersFile = path.join(__dirname, '../users.json');
const docsFile = path.join(__dirname, '../USERS_AND_DB_DOCS.md');

const users = {};
let usersDocContent = `# მომხმარებლების ბაზა და ინსტრუქცია

აქ მოცემულია სისტემის მონაცემთა ბაზის სტრუქტურა და გენერირებული ტესტ-მომხმარებლების სია.

## უსაფრთხოების სტანდარტები
1.  **პაროლის ჰეშირება**: ყველა პაროლი შენახულია \`bcrypt\` ალგორითმით. ბაზაში (**users.json**) პაროლები ღია სახით არ ჩანს!
2.  **ფაილური ბაზა**: მონაცემები გამოყოფილია კოდისგან.

## გენერირებული მომხმარებლები (ტესტირებისთვის)

| სახელი | ელ.ფოსტა | პაროლი (სატესტო) |
| :--- | :--- | :--- |
`;

async function generateUsers() {
    console.log('მომხმარებლების გენერაცია დაწყებულია...');

    for (let i = 1; i <= usersCount; i++) {
        const email = `testuser${i}@example.com`;
        // პაროლი უნდა იყოს რთული: 8+ სიმბოლო, 1 დიდი ასო, 1 ციფრი.
        // სატესტოდ ვიყენებთ: "Password123!" + ინდექსი (რომ უნიკალური იყოს ცოტათი მაინც, თუმცა ყველა ერთნაირიც მოსულა)
        // სიმარტივისთვის ავიღოთ ერთი ძლიერი პაროლი ყველასთვის ან უნიკალური.
        // მოდი იყოს: "SecurePass" + i + "!" (მაგ: SecurePass1!, SecurePass2!...)
        const plainPassword = `SecurePass${i}!`;
        
        // პაროლის ჰეშირება (10 რაუნდი salt)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(plainPassword, salt);

        users[email] = {
            email: email,
            password: hashedPassword, // ინახება ჰეში
            is2faSetup: false, // თავიდან 2FA გამორთულია
            twofaSecret: "" 
        };

        // დოკუმენტაციაში ვწერთ ღია პაროლს რომ იცოდეს იუზერმა რითი შევიდეს
        usersDocContent += `| User ${i} | ${email} | \`${plainPassword}\` |\n`;
    }

    // JSON ფაილის შექმნა
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
    console.log(`[OK] ${usersCount} მომხმარებელი ჩაიწერა ${usersFile}-ში.`);

    // MD ფაილის შექმნა
    fs.writeFileSync(docsFile, usersDocContent);
    console.log(`[OK] დოკუმენტაცია ჩაიწერა ${docsFile}-ში.`);
}

generateUsers();
