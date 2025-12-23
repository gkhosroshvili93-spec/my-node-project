# Future Security Roadmap

(სამომავლო განვითარების გეგმა)

ამჟამად პროექტმა აჩვენა ძირითადი სისუსტეები. სრული დაცვისთვის, რეალურ პროდუქციაში ჩაშვებისას, აუცილებელია შემდეგი ნაბიჯები:

## 1. ავტორიზაციის გაძლიერება (Authentication)

- [ ] **2FA (Two-Factor Authentication)**: მხოლოდ პაროლი არ არის საკმარისი. უნდა დაემატოს SMS კოდი ან Google Authenticator.
- [ ] **Secure Session Management**: ქუქი-ფაილების (Cookies) დაცვა `HttpOnly` და `Secure` დროშებით, რათა XSS შეტევისას მათი მოპარვა (`cookie_stealer.py`) შეუძლებელი გახდეს.

## 2. სერვერის დაცვა (Backend Security)

- [ ] **Real Backend Implementation**: Cloudflare Pages-ის ნაცვლად, სერვერის გადატანა Python (Django) ან Node.js გარემოში, სადაც ავტორიზაცია სერვერზე მოხდება და არა ბრაუზერში.
- [ ] **WAF (Web Application Firewall)**: Cloudflare-ის WAF-ის ჩართვა, რომელიც ავტომატურად დაბლოკავს SQL Injection და XSS მცდელობებს, სანამ ისინი სერვერამდე მიაღწევენ.

## 3. მონაცემთა შენახვა (Data Storage)

- [ ] **Hashing Upgrade**: ამჟამად ვიყენებთ მარტივ შედარებას. საჭიროა გადასვლა `Argon2` ან `Bcrypt` ალგორითმებზე პაროლების ჰეშირებისთვის.
- [ ] **Database Encryption**: ბაზაში შენახული მგრძნობიარე მონაცემების (სახელი, მეილი) დაშიფვრა.

## 4. მონიტორინგი (Monitoring)

- [ ] **Logs & Alerts**: სისტემის დანერგვა, რომელიც ადმინისტრატორს შეატყობინებს (მაგ: Telegram-ზე), თუ ვინმე 5-ჯერ არასწორად შეიყვანს პაროლს (Brute Force მცდელობა).
