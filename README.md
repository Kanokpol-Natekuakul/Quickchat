# QuickGPT - แอปพลิเคชัน AI Chat และ Image Generation

QuickGPT เป็นแอปพลิเคชันเว็บที่ใช้ AI สำหรับการสนทนา (Chat) และสร้างภาพ (Image Generation) โดยใช้ Google Gemini API สำหรับข้อความและ ImageKit สำหรับการสร้างภาพ

## 🚀 คุณสมบัติหลัก

- **AI Chat**: สนทนากับ AI โดยใช้ Google Gemini 2.0 Flash
- **Image Generation**: สร้างภาพจาก prompt โดยใช้ ImageKit AI
- **Credit System**: ระบบเครดิตสำหรับใช้งานบริการ
- **Community Gallery**: แชร์ภาพที่สร้างกับชุมชน
- **Dark/Light Mode**: รองรับธีมทั้งสว่างและมืด
- **Responsive Design**: ใช้งานได้บนทุกอุปกรณ์

## 🛠️ เทคโนโลยีที่ใช้

### Frontend
- **React 19.1.1** - JavaScript Framework
- **Vite 7.1.2** - Build Tool
- **Tailwind CSS 4.1.12** - CSS Framework
- **React Router DOM** - Navigation
- **Axios** - HTTP Client
- **React Hot Toast** - Notification System
- **React Markdown** - Markdown Rendering
- **Moment.js** - Date Formatting
- **PrismJS** - Code Syntax Highlighting

### Backend
- **Node.js** - Runtime Environment
- **Express 5.1.0** - Web Framework
- **MongoDB** - Database
- **Mongoose** - ODM
- **JWT** - Authentication
- **BCryptJS** - Password Hashing
- **Stripe** - Payment Processing
- **ImageKit** - Image Management
- **OpenAI SDK** - AI Integration (สำหรับ Gemini)

## 📋 การติดตั้งและเรียกใช้

### 1. Prerequisites
- Node.js (Version 16+)
- MongoDB Database
- Environment Variables (ดูใน section ถัดไป)

### 2. Clone Repository
```bash
git clone <repository-url>
cd quickgpt
```

### 3. ติดตั้ง Dependencies

#### Backend
```bash
cd server
npm install
```

#### Frontend
```bash
cd client
npm install
```

### 4. ตั้งค่า Environment Variables

สร้างไฟล์ `.env` ในโฟลเดอร์ `server/` และใส่ค่าตัวแปรดังนี้:

```env
# Database
MONGODB_URL=mongodb://localhost:27017

# JWT Secret
JWT_SECRET=your-jwt-secret-key

# Google Gemini API
GEMINI_API_KEY=your-gemini-api-key

# ImageKit Configuration
IMAGEKIT_PUBLIC_KEY=your-imagekit-public-key
IMAGEKIT_PRIVATE_KEY=your-imagekit-private-key
IMAGEKIT_URL_ENDPOINT=your-imagekit-url-endpoint

# Stripe Configuration
STRIPE_SECRET_KEY=your-stripe-secret-key
STRIPE_WEBHOOK_SECRET=your-stripe-webhook-secret

# Server Port
PORT=3000
```

สร้างไฟล์ `.env` ในโฟลเดอร์ `client/` และใส่:

```env
VITE_SERVER_URL=http://localhost:3000
```

### 5. รันแอปพลิเคชัน

#### Backend
```bash
cd server
npm run server    # สำหรับ development
# หรือ
npm start         # สำหรับ production
```

#### Frontend
```bash
cd client
npm run dev       # สำหรับ development
# หรือ
npm run build     # สำหรับ production
npm run preview   # preview production build
```

## 🔌 API Endpoints

### Authentication APIs

#### 1. สมัครสมาชิก
```http
POST /api/user/register
Content-Type: application/json

{
  "name": "ชื่อผู้ใช้",
  "email": "email@example.com",
  "password": "รหัสผ่าน"
}
```

#### 2. เข้าสู่ระบบ
```http
POST /api/user/login
Content-Type: application/json

{
  "email": "email@example.com",
  "password": "รหัสผ่าน"
}
```

#### 3. ดึงข้อมูลผู้ใช้
```http
GET /api/user/data
Authorization: Bearer <token>
```

### Chat APIs

#### 1. สร้างแชทใหม่
```http
GET /api/chat/create
Authorization: Bearer <token>
```

#### 2. ดึงแชททั้งหมดของผู้ใช้
```http
GET /api/chat/get
Authorization: Bearer <token>
```

#### 3. ลบแชท
```http
POST /api/chat/delete
Authorization: Bearer <token>
Content-Type: application/json

{
  "chatId": "chat-id"
}
```

### Message APIs

#### 1. ส่งข้อความแบบข้อความ
```http
POST /api/message/text
Authorization: Bearer <token>
Content-Type: application/json

{
  "chatId": "chat-id",
  "prompt": "คำถามหรือข้อความ",
  "isPublished": false
}
```

#### 2. สร้างภาพจาก Prompt
```http
POST /api/message/image
Authorization: Bearer <token>
Content-Type: application/json

{
  "chatId": "chat-id",
  "prompt": "คำอธิบายภาพที่ต้องการสร้าง",
  "isPublished": true
}
```

### Credit System APIs

#### 1. ดูแพ็กเกจเครดิต
```http
GET /api/credit/plan
```

#### 2. ซื้อเครดิต
```http
POST /api/credit/purchase
Authorization: Bearer <token>
Content-Type: application/json

{
  "planId": "basic" | "pro" | "premium"
}
```

### Community APIs

#### 1. ดูภาพที่แชร์ในชุมชน
```http
GET /api/user/published-images
```

## 🔧 การตั้งค่า API Services

### 1. Google Gemini API
1. ไปที่ [Google AI Studio](https://makersuite.google.com/app/apikey)
2. สร้าง API Key ใหม่
3. ใส่ค่าใน `GEMINI_API_KEY`

### 2. ImageKit
1. สมัครสมาชิกที่ [ImageKit.io](https://imagekit.io)
2. ไปที่ Dashboard > Developer Options
3. คัดลอก Public Key, Private Key, และ URL Endpoint
4. ใส่ค่าใน environment variables

### 3. Stripe Payment
1. สมัครสมาชิกที่ [Stripe](https://stripe.com)
2. ไปที่ Dashboard > Developers > API Keys
3. คัดลอก Secret Key
4. ตั้งค่า Webhook สำหรับ payment events
5. ใส่ค่าใน environment variables

### 4. MongoDB
1. ติดตั้ง MongoDB locally หรือใช้ MongoDB Atlas
2. ใส่ connection string ใน `MONGODB_URL`

## 💳 ระบบเครดิต

- **Text Generation**: 1 เครดิต/คำถาม
- **Image Generation**: 2 เครดิต/ภาพ
- **สมาชิกใหม่**: ได้เครดิตฟรี 20 เครดิต

### แพ็กเกจเครดิต:
- **Basic**: $10 = 100 เครดิต
- **Pro**: $20 = 500 เครดิต  
- **Premium**: $30 = 1000 เครดิต

## 🎨 การใช้งาน Frontend

### การเรียกใช้ API ใน React
```javascript
import { useAppContext } from './context/AppContext'

const Component = () => {
  const { axios, token } = useAppContext()
  
  const sendMessage = async (prompt) => {
    const { data } = await axios.post('/api/message/text', {
      chatId: selectedChat._id,
      prompt,
      isPublished: false
    }, {
      headers: { Authorization: token }
    })
    
    if (data.success) {
      // Handle success
    }
  }
}
```

### Theme System
แอปรองรับทั้ง Light และ Dark Mode โดยใช้ Tailwind CSS และ Local Storage

## 📁 โครงสร้างโปรเจค

```
quickgpt/
├── client/                 # Frontend React App
│   ├── src/
│   │   ├── components/     # React Components
│   │   ├── pages/          # Page Components
│   │   ├── context/        # Context API
│   │   ├── assets/         # Static Assets
│   │   └── ...
│   └── ...
└── server/                 # Backend Express App
    ├── configs/            # Configuration Files
    ├── controllers/        # Route Controllers
    ├── middlewares/        # Express Middlewares
    ├── models/            # MongoDB Models
    ├── routes/            # API Routes
    └── server.js          # Main Server File
```

## 🚀 การ Deploy

### Frontend (Vercel)
```bash
cd client
npm run build
# Deploy บน Vercel
```

### Backend (Vercel/Heroku)
```bash
cd server
# ตั้งค่า environment variables บน platform
# Deploy ตาม documentation ของแต่ล platform
```

## 🐛 การแก้ไขปัญหาที่พบบ่อย

### 1. Authentication Error
- ตรวจสอบ JWT_SECRET ใน environment variables
- ตรวจสอบ token format ใน request headers

### 2. API Connection Error
- ตรวจสอบ VITE_SERVER_URL ใน client
- ตรวจสอบ CORS configuration

### 3. Database Connection Error
- ตรวจสอบ MONGODB_URL
- ตรวจสอบการเชื่อมต่อ network

### 4. Payment Webhook Error
- ตรวจสอบ Stripe webhook secret
- ตรวจสอบ endpoint URL ใน Stripe dashboard

## 📝 การพัฒนาเพิ่มเติม

### เพิ่มฟีเจอร์ใหม่:
1. สร้าง API endpoint ใน `server/routes/`
2. สร้าง controller ใน `server/controllers/`
3. เพิ่ม frontend component ใน `client/src/components/`
4. อัพเดท context หรือ state management

# credit

- https://youtu.be/YEPH-DWnDPE?si=fLDAnEqbudSI3tDy

ฝึกฝนและศึกษาจากคลิปนี้

### การทดสอบ:
- ใช้ Postman หรือ Thunder Client สำหรับทดสอบ API
- ใช้ React DevTools สำหรับ debug frontend

---

**หมายเหตุ**: อย่าลืมเปลี่ยน `your-api-keys` และ `your-email` เป็นค่าจริงของคุณก่อนใช้งาน
