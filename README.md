# node-auth-security-assessment
# 🛡️ Node.js Authentication Security Hardening Project

This project is a **security-audited and enhanced** version of a Node.js authentication system. Built using **Node.js**, **Express**, and **MongoDB**, this application underwent a structured analysis to identify security vulnerabilities, followed by remediation using modern best practices.

> 📌 This repository is part of a DevelopersHub.co **Cybersecurity Internship Project** that involves auditing an existing authentication system, finding flaws, and implementing robust countermeasures.

---

## 🔍 Project Goals

- ✅ Audit an existing Node.js authentication app  
- ✅ Identify security flaws (e.g., brute-force attacks, missing headers, weak CORS policies)  
- ✅ Implement and test security enhancements  
- ✅ Log intrusion attempts and integrate with host-level tools (e.g., Fail2Ban)

---

## 📁 Project Structure

project-root/  
├── server.js # Entry point  
├── package.json # Project dependencies  
├── .env # Sensitive keys (excluded from Git)  
├── /app  
│ ├── config/db.config.js # MongoDB configuration  
│ ├── models/ # Mongoose models (User, Role)  
│ ├── controllers/ # Auth logic (signup, signin, signout)  
│ └── routes/ # Auth and user routes  

---

## 🧪 Features & Enhancements

### ✅ 1. Intrusion Detection Logging

- Logs every failed login attempt with IP, username, and reason.
- Stored at: `/var/log/app-login-failures.log`


<img width="975" height="235" alt="image" src="https://github.com/user-attachments/assets/21c27336-c384-4aa7-8f26-71cc9291949a" />

### ✅ 2. Rate Limiting
Limits each IP to 100 requests per 15 minutes.

Helps mitigate brute-force and DDoS attacks.

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later."
}));
<img width="975" height="339" alt="image" src="https://github.com/user-attachments/assets/eda6a4e0-f1fb-4f83-a60f-95db0339b33e" />
<img width="975" height="544" alt="image" src="https://github.com/user-attachments/assets/c9c074b2-fad2-4c18-a1ec-7c3df03196b3" />

### ✅ 3. CORS Restriction
Configured to accept requests only from whitelisted origins.

Supports credentials.

pp.use(cors());
/* for Angular Client (withCredentials) */
 app.use(
   cors({
     credentials: true,
     origin: ["http://localhost:8081"],
   })
 );
 
### ✅ 4. API Key Protection
Secures all API routes using a static API key.

Expected via custom header: x-api-key

const API_KEY = process.env.API_KEY;

function checkApiKey(req, res, next) {
  if (req.headers['x-api-key'] !== API_KEY) {
    return res.status(403).json({ message: "Forbidden. Invalid API Key." });
  }
  next();
}

app.use("/api", checkApiKey);
### ✅ 5. Secure HTTP Headers (Helmet)
Sets 11+ HTTP security headers using helmet

Adds:

Content-Security-Policy

Strict-Transport-Security

X-Frame-Options

app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: []
  },
}));
<img width="975" height="276" alt="image" src="https://github.com/user-attachments/assets/7124d4dc-3242-46a8-9f24-066042e3b17e" />

### ✅ 6. Integration with Fail2Ban
Created a jail in Fail2Ban that monitors /var/log/app-login-failures.log

Automatically bans IPs after repeated failed login attempts

## 🧪 Testing & Demo

This section demonstrates the implemented security features with live testing results and screenshots captured using tools like **curl**.

*Sample Request:*
curl -X POST http://localhost:8080/api/auth/signin \
  -H "Content-Type: application/json" \
  -H "x-api-key: **********" \
  -d '{"username":"admin", "password":"wrong"}'

---

### 🔐 1. Intrusion Detection & Monitoring (Fail2Ban Integration)

The system logs every failed login attempt with IP, username, and reason to a dedicated log file:  
`/var/log/app-login-failures.log`

These logs are monitored using **Fail2Ban**, which can automatically block malicious IPs after repeated failures.

#### 🖼️ Screenshots:
<img width="938" height="945" alt="Fail2Ban Log" src="https://github.com/user-attachments/assets/098f780c-2e2f-4d2b-926e-8b953863e811" />
<img width="975" height="179" alt="Fail2Ban Jail Setup" src="https://github.com/user-attachments/assets/d8c58d94-7fe5-4712-8ce3-bf8b2a65f8d5" />
<img width="975" height="235" alt="Fail2Ban Log Format" src="https://github.com/user-attachments/assets/69344d87-3298-429a-8c49-2f3238f322ee" />
<img width="870" height="331" alt="Fail2Ban IP Ban Confirmation" src="https://github.com/user-attachments/assets/f8f8cece-355a-47b3-8e44-3948129d4760" />

✅ **Result**: Unauthorized login attempts are detected, logged, and blocked in real time.

---

### 🔑 2. API Security with API Key Authentication

Each request to protected endpoints requires a valid API key in the header (`x-api-key`). Invalid or missing keys are denied with `403 Forbidden`.

#### 🖼️ Screenshot:
<img width="975" height="53" alt="API Key Header Check" src="https://github.com/user-attachments/assets/b4ebab45-2123-4e7f-87a9-5550c41b5e02" />

✅ **Result**: Access is restricted to authorized clients only, preventing misuse of public endpoints.

---

### 🛡️ 3. Security Headers & CSP Implementation (Helmet Middleware)

Implemented using the `helmet` middleware and customized Content Security Policy (CSP) to prevent:

- XSS attacks  
- Clickjacking  
- Code injection

Curl response headers confirm the presence of security headers:

- `Content-Security-Policy`  
- `Strict-Transport-Security` (HSTS)  
- `X-Content-Type-Options`, `X-Frame-Options`, etc.

#### 🖼️ Screenshots:
<img width="975" height="276" alt="CSP Headers Confirmed" src="https://github.com/user-attachments/assets/d6532b9b-2f25-481b-9391-0922c1959f4c" />
<img width="975" height="276" alt="HSTS & Helmet Headers" src="https://github.com/user-attachments/assets/699865e8-4f92-46c0-8fca-b7fae3e4173e" />

✅ **Result**: All necessary security headers are enforced on HTTP responses to prevent client-side vulnerabilities.

---

### 🌐 4. HTTP Rate Limiting (Brute-Force Mitigation)

Using `express-rate-limit`, each IP address is limited to **100 requests per 15 minutes**. After exceeding the limit, requests are blocked with a `429 Too Many Requests` response.

#### 🖼️ Screenshot:
<img width="975" height="544" alt="Rate Limiting Triggered" src="https://github.com/user-attachments/assets/a6013bb4-eed0-439f-87a0-cf042c50625d" />

✅ **Result**: Prevents brute-force login attempts and slows down bot-based abuse.

---

🔐 Environment Variables  
Store sensitive data in a .env file:  
API_KEY=*************  

🚫 Do not hardcode secrets in your codebase.  

📚 Technologies Used  
Node.js + Express.js  

MongoDB + Mongoose  

Helmet (security headers)  

express-rate-limit (rate limiting)  

dotenv (env management)  

Fail2Ban (external)  

👨‍💻 Author  
Muhammad Hammad Tahir  
Cybersecurity Developer — DeveloperHub Project 2  
🔗 GitHub: @MuhammadHammadTahir

📜 License  
This project was developed for educational purposes as part of a cybersecurity learning initiative. Feel free to fork, explore, or adapt.
