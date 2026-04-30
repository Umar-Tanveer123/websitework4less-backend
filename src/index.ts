import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'secret';

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

import fs from 'fs';
import multer from 'multer';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

// Setup nodemailer transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Setup multer for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '-'));
  }
});
const upload = multer({ storage });

// --- AUTH ROUTES ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  // For local testing, we'll auto-create the admin if they don't exist
  // and they use the specific dev email.
  let user = await prisma.user.findUnique({ where: { email } });
  
  if (!user && email === 'umertanver0331@gmail.com') {
    const hashedPassword = await bcrypt.hash(password, 10);
    user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name: 'Admin',
      }
    });
  }

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const resetTokenExpiry = new Date(Date.now() + 600000); // 10 minutes (shorter for OTP)

    await prisma.user.update({
      where: { email },
      data: { resetToken: otp, resetTokenExpiry }
    });
    
    await transporter.sendMail({
      from: `"Website Work 4 Less Admin" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your Password Reset OTP",
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 30px; border: 1px solid #eee; border-radius: 20px; background-color: #ffffff;">
          <h2 style="color: #333; text-align: center;">Password Reset OTP</h2>
          <p style="color: #666; text-align: center;">Use the code below to reset your password. This code will expire in 10 minutes.</p>
          <div style="margin: 30px 0; text-align: center;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #5551FF; background-color: #f0f0ff; padding: 15px 30px; border-radius: 10px;">${otp}</span>
          </div>
          <p style="color: #999; font-size: 12px; text-align: center;">If you didn't request this, you can safely ignore this email.</p>
        </div>
      `,
    });

    res.json({ success: true, message: 'OTP sent to your email' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || user.resetToken !== otp || !user.resetTokenExpiry || user.resetTokenExpiry < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { email },
      data: { 
        password: hashedPassword, 
        resetToken: null, 
        resetTokenExpiry: null 
      }
    });

    res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Middleware to authenticate JWT
const authenticateToken = (req: any, res: any, next: any) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/api/auth/change-password', authenticateToken, async (req: any, res: any) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.userId;

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const validPassword = await bcrypt.compare(oldPassword, user.password);
  if (!validPassword) return res.status(400).json({ error: 'Incorrect old password' });

  const hashedPassword = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword }
  });

  res.json({ success: true, message: 'Password updated successfully' });
});

app.post('/api/auth/register-admin', authenticateToken, async (req: any, res: any) => {
  const { email, password, name } = req.body;

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) return res.status(400).json({ error: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: {
      email,
      password: hashedPassword,
      name,
    }
  });

  res.json({ success: true, user: { id: user.id, email: user.email, name: user.name } });
});

// --- NEW: OTP-Based Self Registration ---
app.post('/api/auth/register-otp', async (req, res) => {
  const { email } = req.body;
  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 600000); // 10 minutes

    // Store OTP in a temporary "Pending" state (We can use a dedicated table or reuse User with a flag)
    // For simplicity, we'll use a hidden field in the User table but marked as "inactive" or just store in memory/cache.
    // Here we'll create a "shadow" user or update the existing one if it was incomplete.
    
    // Better: We'll just send the OTP and verify it in the next step along with the registration data.
    // But we need to store the OTP somewhere. Let's use a simple global Map for now or the DB.
    // Let's use the User table with a specific flag if needed, or just send it.
    
    // To keep it clean, let's just send the OTP. The frontend will send it back with the full data.
    // We'll sign the OTP into a temporary JWT so the server can verify it later without a DB session.
    const registrationToken = jwt.sign({ email, otp }, JWT_SECRET, { expiresIn: '10m' });

    await transporter.sendMail({
      from: `"Website Work 4 Less Admin" <${process.env.SMTP_USER}>`,
      to: email,
      subject: "Your Registration OTP",
      html: `
        <div style="font-family: sans-serif; max-width: 600px; margin: auto; padding: 30px; border: 1px solid #eee; border-radius: 20px; background-color: #ffffff;">
          <h2 style="color: #333; text-align: center;">Welcome to the Team!</h2>
          <p style="color: #666; text-align: center;">Use the code below to complete your Admin registration.</p>
          <div style="margin: 30px 0; text-align: center;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #5551FF; background-color: #f0f0ff; padding: 15px 30px; border-radius: 10px;">${otp}</span>
          </div>
          <p style="color: #999; font-size: 12px; text-align: center;">This code will expire in 10 minutes.</p>
        </div>
      `,
    });

    res.json({ success: true, registrationToken });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send registration OTP' });
  }
});

app.post('/api/auth/register-verify', async (req, res) => {
  const { email, password, name, otp, registrationToken } = req.body;
  
  try {
    // Verify the temporary token
    const decoded: any = jwt.verify(registrationToken, JWT_SECRET);
    
    if (decoded.email !== email || decoded.otp !== otp) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      }
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (err) {
    res.status(400).json({ error: 'Invalid or expired registration session' });
  }
});


// --- UPLOAD ROUTE ---
app.post('/api/upload', authenticateToken, upload.single('image'), (req: any, res: any) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image uploaded' });
  }
  const imageUrl = `http://localhost:${PORT}/uploads/${req.file.filename}`;
  res.json({ url: imageUrl });
});

// --- POST ROUTES ---
app.get('/api/posts', async (req, res) => {
  const posts = await prisma.post.findMany({
    orderBy: { createdAt: 'desc' }
  });
  res.json(posts);
});

app.get('/api/posts/:slug', async (req, res) => {
  const post = await prisma.post.findUnique({
    where: { slug: req.params.slug }
  });
  if (!post) return res.status(404).json({ error: 'Post not found' });
  res.json(post);
});

app.post('/api/posts', authenticateToken, async (req: any, res: any) => {
  const { title, slug, content, excerpt, thumbnail, published } = req.body;
  const authorId = req.user.userId;

  try {
    const post = await prisma.post.create({
      data: {
        title, slug, content, excerpt, thumbnail, published, authorId
      }
    });
    res.json(post);
  } catch (err) {
    res.status(400).json({ error: 'Failed to create post (slug might be taken)' });
  }
});

app.put('/api/posts/:id', authenticateToken, async (req: any, res: any) => {
  const { title, slug, content, excerpt, thumbnail, published } = req.body;
  
  try {
    const post = await prisma.post.update({
      where: { id: req.params.id },
      data: { title, slug, content, excerpt, thumbnail, published }
    });
    res.json(post);
  } catch (err) {
    res.status(400).json({ error: 'Failed to update post' });
  }
});

app.delete('/api/posts/:id', authenticateToken, async (req: any, res: any) => {
  try {
    await prisma.post.delete({
      where: { id: req.params.id }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Failed to delete post' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
