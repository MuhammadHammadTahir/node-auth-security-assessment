# node-auth-security-assessment
🛡️ Node.js Authentication Security Hardening Project

This project is a security-audited and enhanced version of a Node.js authentication system. Built using Node.js, Express, and MongoDB, this application underwent a structured analysis to identify security vulnerabilities, followed by remediation using modern best practices.

📌 This repository is part of a DevelopersHub.co Cybersecurity internship Project that involves auditing an existing authentication system, finding flaws, and implementing robust countermeasures.

🔍 Project Goals

Audit an existing Node.js authentication app

Identify security flaws (e.g., brute-force attacks, missing headers, weak CORS policies)

Implement and test security enhancements

Log intrusion attempts and integrate with host-level tools (e.g., Fail2Ban)

📁 Project Structure

project-root/
├── server.js                  # Entry point
├── package.json              # Project dependencies
├── .env                      # Sensitive keys (excluded from Git)
├── /app
│   ├── config/db.config.js   # MongoDB configuration
│   ├── models/               # Mongoose models (User, Role)
│   ├── controllers/          # Auth logic (signup, signin, signout)
│   └── routes/               # Auth and user routes

🧪 Features & Enhancements

✅ 1. Intrusion Detection Logging

Logs every failed login attempt with IP, username, and reason.

Stored at: /var/log/app-login-failures.log

2025-07-11T10:03:21.673Z - Failed login from IP: 192.168.1.5, username: testuser, reason: Invalid password

✅ 2. Rate Limiting

Limits each IP to 100 requests per 15 minutes.

Helps mitigate brute-force and DDoS attacks.

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests from this IP, please try again later."
}));

✅ 3. CORS Restriction

Configured to accept requests only from whitelisted origins.

Supports credentials.

app.use(cors({
  origin: ["http://localhost:8081"],
  credentials: true
}));

✅ 4. API Key Protection

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

✅ 5. Secure HTTP Headers (Helmet)

Sets 11+ HTTP headers using helmet

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

✅ 7. Integration with Fail2Ban

Created a jail in Fail2Ban that monitors /var/log/app-login-failures.log

Automatically bans IPs after repeated failures

🧪 Testing & Demo

Use Postman or curl:

curl -X POST http://localhost:8080/api/auth/signin \
  -H "Content-Type: application/json" \
  -H "x-api-key: supersecretkey" \
  -d '{"username":"admin", "password":"wrong"}'

🔐 Environment Variables

Store these in a .env file:

MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/app
API_KEY=supersecretkey

Do not hardcode secrets in your codebase.

📚 Technologies Used

Node.js + Express.js

MongoDB + Mongoose

Helmet

express-rate-limit

dotenv

Fail2Ban (external)

👨‍💻 Author

Muhammad Hammad TahirCybersecurity Developer — DeveloperHub Project 2GitHub: @MuhammadHammadTahir

📜 License

This project was developed for educational purposes as part of a cybersecurity learning initiative. Feel free to fork, explore, or adapt.

📸 Screenshots (Placeholders)


