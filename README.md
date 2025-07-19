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
<img width="975" height="235" alt="image" src="https://github.com/user-attachments/assets/0b1e2260-1a35-4fd0-82b1-41f0d52dbb0f" />

### ✅ 2. Rate Limiting
Limits each IP to 100 requests per 15 minutes.

Helps mitigate brute-force and DDoS attacks.

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later."
}));
<img width="975" height="339" alt="image" src="https://github.com/user-attachments/assets/199807ab-2f79-4d32-aba3-59d0e4394b8c" />
<img width="975" height="544" alt="image" src="https://github.com/user-attachments/assets/c818cddb-81f6-4975-99d1-47e265336c1f" />

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
<img width="975" height="276" alt="image" src="https://github.com/user-attachments/assets/a4dbc25d-55e7-458c-8c14-482ff52ad551" />

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
<img width="938" height="945" alt="image" src="https://github.com/user-attachments/assets/b6c921e0-5502-4594-9153-ad23c914b29f" />

<img width="975" height="179" alt="image" src="https://github.com/user-attachments/assets/b523a2da-65ea-4aa7-9333-cb5f2a9fff5e" />

<img width="975" height="235" alt="image" src="https://github.com/user-attachments/assets/ad20f02c-7ab6-40a6-80b5-ff35ad992b59" />

<img width="870" height="331" alt="image" src="https://github.com/user-attachments/assets/daf930d2-ee43-47b9-8774-f60245aecda4" />


✅ **Result**: Unauthorized login attempts are detected, logged, and blocked in real time.

---

### 🔑 2. API Security with API Key Authentication

Each request to protected endpoints requires a valid API key in the header (`x-api-key`). Invalid or missing keys are denied with `403 Forbidden`.

#### 🖼️ Screenshot:

<img width="1301" height="69" alt="image" src="https://github.com/user-attachments/assets/1c3e00bf-e25a-4c96-a863-2d5a6d62bc48" />

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

<img width="975" height="276" alt="image" src="https://github.com/user-attachments/assets/5eca74e8-6adf-49ce-985d-1cb6e5d0b9ba" />

<img width="975" height="667" alt="image" src="https://github.com/user-attachments/assets/45024147-59f7-4ea2-9787-e82199ad4aa0" />


✅ **Result**: All necessary security headers are enforced on HTTP responses to prevent client-side vulnerabilities.

---

### 🌐 4. HTTP Rate Limiting (Brute-Force Mitigation)

Using `express-rate-limit`, each IP address is limited to **100 requests per 15 minutes**. After exceeding the limit, requests are blocked with a `429 Too Many Requests` response.

#### 🖼️ Screenshot:
<img width="975" height="386" alt="image" src="https://github.com/user-attachments/assets/6f2f2f0a-b47e-4f25-b185-fb666996ee3a" />

<img width="723" height="45" alt="image" src="https://github.com/user-attachments/assets/41dd0418-86fe-4803-9c9d-bc81496ee29d" />


✅ **Result**: Prevents brute-force login attempts and slows down bot-based abuse.

---

### 🔐 Environment Variables  
Store sensitive data in a .env file:  
API_KEY=*************  

🚫 Do not hardcode secrets in your codebase.  

### 📚 Technologies Used  
Node.js + Express.js  

MongoDB + Mongoose  

Helmet (security headers)  

express-rate-limit (rate limiting)  

dotenv (env management)  

Fail2Ban (external)  

### 👨‍💻 Author  
Muhammad Hammad Tahir  
Cybersecurity Developer — DeveloperHub Project 2  
🔗 GitHub: @MuhammadHammadTahir

### 📜 License  
This project was developed for educational purposes as part of a cybersecurity learning initiative. Feel free to fork, explore, or adapt.
