# LOGIN TEST 

##  რატომ შევქმენი ეს პროექტი?

ეს პროექტი შექმნილია სალოგინო ფორმების უსაფრთხოების ტესტირებისთვის.
იგი აერთიანებს ყველაზე გავრცელებულ თავდასხმების ტიპებს და უსაფრთხოების
სისუსტეებს, რათა დეველოპერებმა შეძლონ თავიანთი აპლიკაციების შემოწმება.


### პროექტში გავუშვი პითონის ტესტები:

| ფაილი | ტესტი |
|-------|-------|
| `run_lockout_tester |  ანგარიშის ბლოკირება |
| `run_bruteforce |  ბრუტფორსი |
| `run_sql_injection |  SQL ინექცია |
| `run_xss_test |  XSS ტესტი |
| `run_admin_fuzzer |  ადმინ ფაზერი |
| `run_session_stealer |  სესიის მოპარვა |
| `run_cookie_stealer |  ქუქი სტილერი |
| `run_clickjack_test |  კლიკჯეკინგი |
| `run_log_monitor |  ლოგების მონიტორი |
| `run_social_brute |  სოციალური ბრუტფორსი |
| `run_sentinel_attack |  სენტინელ შეტევა |

 


##  შედეგი
ჩამოთვლილთაგან ყველა ტესტის გაშვება login ფორმამ წარმატებით გადალახა:

[1]   Account Lockout Test
[2]   Brute Force Test
[3]   SQL Injection Test
[4]   XSS Test
[5]   Session Stealer
[6]   Cookie Stealer
[7]   Clickjacking Test
[8]   Admin Fuzzer
[9]   Log Monitor
[10]  Social Brute Force
[11]  Sentinel Attack

##  მნიშვნელოვანი გაფრთხილებები

###  კანონიერობა:
 Educational Use Only - მხოლოდ საგანმანათლებლო გამოყენებისთვის
> გამოიყენე მხოლოდ შენს სისტემებზე!
> უნებართვო ტესტირება კანონსაწინააღმდეგოა!
ყველა მსგავსი მეთოდის გამოყენება დაუშვებელია და კანონით ისჯება თუ არ გაქვთ ამის წერილობითი ნებართვა

###  ტექნიკური:
- Python 3.x 
- Selenium 
- Chrome/ChromeDriver საჭირო Selenium ტესტებისთვის

 შეტევის სტრუქტურა

├── run_*.bat                       
│
├── Account_Lockout/
├── Advanced_Tests/
├── Brute_Force_Test/
├── SQL_Injection_Test/
├── XSS_Test/
└── ... (other test folders)


**შექმნილია ❤️-ით გიორგი ხოსროშვილის მიერ**  
 



