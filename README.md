# WAF Middleware

[![npm version](https://badge.fury.io/js/waf-middleware.svg)](https://www.npmjs.com/package/waf-middleware)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A middleware for **NestJS/Express.js** that provides **Web Application Firewall (WAF)** protection against SQL injection, XSS, and other malicious inputs.

---

## 🚀 Features

✅ **SQL Injection Protection** - Detects and blocks SQL injection attempts in query and body parameters.  
✅ **XSS Protection** - Blocks script injections (`<script>`, `javascript:`, etc.).  
✅ **Sorting & Field Name Validation** - Ensures `order_field` and `sort` parameters are sanitized.  
✅ **Automatic Parameter Normalization** - Converts query keys to lowercase for consistency.  
✅ **No Hardcoded Parameter Names** - Works dynamically with all APIs without modifying the middleware.  

---

## 📦 Installation

Install via **npm**:

```bash
npm install waf-middleware
```

or with **yarn**:

```bash
yarn add waf-middleware
```

---

## 🚀 Usage

### **NestJS Integration**
In your `main.ts`, apply the middleware globally:

```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { WafMiddleware } from 'waf-middleware';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    
    app.use(new WafMiddleware().use);
    
    await app.listen(3000);
}
bootstrap();
```

### **Express.js Integration**
If you’re using **Express.js**, you can apply it like this:

```typescript
import express from 'express';
import { WafMiddleware } from 'waf-middleware';

const app = express();
const waf = new WafMiddleware();

app.use((req, res, next) => waf.use(req, res, next));

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
```

---

## 🔒 Security Features

### 1️⃣ **SQL Injection Protection**
Blocks attempts like:
- `?order_field=category' OR 1=1 --`
- `?transactionID=12345; DROP TABLE users;`

### 2️⃣ **XSS Protection**
Blocks:
- `<script>alert('XSS')</script>`
- `javascript:alert('XSS')`

### 3️⃣ **Sorting & Field Validation**
Only allows valid sorting values (`ASC`, `DESC`) and ensures fields are alphanumeric.

---

## 🛠️ Development & Contribution

Want to contribute? Fork this repo and submit a **pull request**! 🚀

### **Clone the Repository**
```bash
git clone https://github.com/rick001/waf-middleware.git
cd waf-middleware
npm install
```

---

## 📜 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## ⭐ Support the Project!

If you found this useful, consider giving a ⭐ on [GitHub](https://github.com/rick001/waf-middleware)! 💖
