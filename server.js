import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

// ------------------- DIRNAME POLYFILL FOR ES MODULES -------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ------------------- APP & MIDDLEWARE -------------------
const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false, // Adjust as needed for your frontend
  crossOriginEmbedderPolicy: false
}));

// Rate limiter (basic)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'), // requests per window
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// CORS setup - allow list or wildcard via CORS_ORIGIN env
const rawOrigins = process.env.CORS_ORIGIN || 'http://localhost:3000';
const allowedOrigins = rawOrigins.split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, callback) => {
    // allow non-browser requests (e.g. curl) if no origin
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Validate required environment variables
if (!process.env.JWT_SECRET) {
  console.error('❌ JWT_SECRET environment variable is required');
  process.exit(1);
}

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Conditionally serve uploads (set SERVE_UPLOADS=false to disable static serving)
if (process.env.SERVE_UPLOADS !== 'false') {
  app.use('/uploads', express.static(UPLOAD_DIR));
}

// ------------------- DATABASE -------------------
const db = new Database(process.env.DB_FILE || 'database.sqlite');

// Enable foreign keys and better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const columnExists = (tableName, columnName) => {
  try {
    const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
    return columns.some(col => col.name === columnName);
  } catch (error) {
    return false;
  }
};

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'editor',
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blog_posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  excerpt TEXT,
  authorId INTEGER,
  category TEXT NOT NULL,
  imageUrl TEXT,
  publishedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  isPublished BOOLEAN DEFAULT 1,
  FOREIGN KEY (authorId) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  location TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS workshops (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  facilitator TEXT NOT NULL,
  location TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS webinars (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  date TEXT NOT NULL,
  speaker TEXT NOT NULL,
  imageUrl TEXT,
  registrationUrl TEXT,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS careers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  requirements TEXT,
  location TEXT NOT NULL,
  deadline TEXT NOT NULL,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contact_forms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  isRead BOOLEAN DEFAULT 0,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS newsletter_subscribers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  isActive BOOLEAN DEFAULT 1,
  subscribedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS donations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  amount REAL NOT NULL,
  message TEXT,
  paymentMethod TEXT NOT NULL,
  isProcessed BOOLEAN DEFAULT 0,
  createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

// Migrations (unchanged)
if(!columnExists('blog_posts', 'excerpt')) {
  db.exec(`ALTER TABLE blog_posts ADD COLUMN excerpt TEXT;`);
  console.log('✅ Added excerpt column to blog_posts table');
}

if (!columnExists('blog_posts', 'isPublished')) {
  db.exec('ALTER TABLE blog_posts ADD COLUMN isPublished BOOLEAN DEFAULT 1');
  console.log('✅ Added isPublished column to blog_posts');
}

if (!columnExists('blog_posts', 'updatedAt')) {
  db.exec('ALTER TABLE blog_posts ADD COLUMN updatedAt DATETIME');
  db.exec('UPDATE blog_posts SET updatedAt = CURRENT_TIMESTAMP WHERE updatedAt IS NULL');
  console.log('✅ Added updatedAt column to blog_posts');
}

const tables = ['events', 'workshops', 'webinars', 'careers'];
tables.forEach(table => {
  if (!columnExists(table, 'updatedAt')) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`);
    console.log(`✅ Added updatedAt column to ${table}`);
  }
});

if (!columnExists('contact_forms', 'isRead')) {
  db.exec('ALTER TABLE contact_forms ADD COLUMN isRead BOOLEAN DEFAULT 0');
  console.log('✅ Added isRead column to contact_forms');
}

if (!columnExists('newsletter_subscribers', 'isActive')) {
  db.exec('ALTER TABLE newsletter_subscribers ADD COLUMN isActive BOOLEAN DEFAULT 1');
  console.log('✅ Added isActive column to newsletter_subscribers');
}

// Create default admin user if allowed by env (set CREATE_DEFAULT_ADMIN=false to skip)
if (process.env.CREATE_DEFAULT_ADMIN !== 'false') {
  const adminCheck = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@radianthope.com');
  if (!adminCheck) {
    const hashedPassword = bcrypt.hashSync(process.env.DEFAULT_ADMIN_PWD || 'admin123', 10);
    db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)')
      .run('Admin User', 'admin@radianthope.com', hashedPassword, 'admin');
    console.log('✅ Default admin user created: admin@radianthope.com (password from DEFAULT_ADMIN_PWD or admin123)');
  }
} else {
  console.log('ℹ️ Skipping default admin creation (CREATE_DEFAULT_ADMIN=false)');
}

// ------------------- HELPER FUNCTIONS -------------------
const sanitizeInput = (input) => {
  if (typeof input === 'string') {
    return input.trim().replace(/[<>]/g, '');
  }
  return input;
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const deleteFile = (filePath) => {
  if (filePath && filePath.startsWith('/uploads/')) {
    const fullPath = path.join(__dirname, filePath);
    if (fs.existsSync(fullPath)) {
      fs.unlinkSync(fullPath);
    }
  }
};

const generateExcerpt = (content, maxLength = 150) => {
  const plainText = content.replace(/<[^>]*>/g, '');
  return plainText.length > maxLength 
    ? plainText.substring(0, maxLength) + '...' 
    : plainText;
};

// ------------------- UPLOADS (multer) -------------------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  }
});

// ------------------- AUTH HELPERS -------------------
const getUserById = (id) => {
  return db.prepare('SELECT id, name, email, role, password, createdAt FROM users WHERE id = ?').get(id);
};

const authMiddleware = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).send({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = getUserById(decoded.id);
    
    if (!user) {
      return res.status(401).send({ error: 'Invalid token.' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(401).send({ error: 'Invalid token.' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    return res.status(403).send({ error: 'Admin access required.' });
  }
  next();
};

const editorMiddleware = (req, res, next) => {
  if (!['admin', 'editor'].includes(req.user?.role)) {
    return res.status(403).send({ error: 'Editor access required.' });
  }
  next();
};

// ------------------- AUTH ROUTES -------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    let { name, email, password, role = 'editor' } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    
    if (!name || !email || !password) {
      return res.status(400).send({ error: 'Name, email, and password are required.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (password.length < 6) {
      return res.status(400).send({ error: 'Password must be at least 6 characters long.' });
    }
    
    if (name.length > 100) {
      return res.status(400).send({ error: 'Name is too long.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    const info = stmt.run(name, email, hashedPassword, role);
    
    const user = { 
      id: info.lastInsertRowid, 
      name, 
      email, 
      role,
      createdAt: new Date().toISOString()
    };
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
    res.status(201).send({ user, token });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).send({ error: 'Email already exists.' });
    }
    res.status(400).send({ error: 'Registration failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).send({ error: 'Email and password are required.' });
    }
    
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
    const safeUser = { 
      id: user.id, 
      name: user.name, 
      email: user.email, 
      role: user.role, 
      createdAt: user.createdAt 
    };
    
    res.send({ user: safeUser, token });
  } catch (err) {
    res.status(500).send({ error: 'Login failed.' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.send(safeUser);
});

// ------------------- HEALTH CHECK -------------------
app.get('/api/health', (req, res) => {
  try {
    // basic DB check
    const row = db.prepare('SELECT 1 as ok').get();
    res.send({
      status: 'ok',
      db: !!row,
      time: new Date().toISOString(),
      version: '1.0.0'
    });
  } catch (err) {
    res.status(500).send({ status: 'error', error: 'DB check failed' });
  }
});

// ------------------- BLOG ROUTES -------------------
app.get('/api/blog', (req, res) => {
  try {
    const { page = 1, limit = 10, category, search, publishedOnly = true } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    let params = [];
    
    if (publishedOnly) {
      whereClause = 'WHERE b.isPublished = 1';
    }
    
    if (category) {
      whereClause += whereClause ? ' AND b.category = ?' : 'WHERE b.category = ?';
      params.push(category);
    }
    
    if (search) {
      const searchCondition = `(b.title LIKE ? OR b.content LIKE ? OR u.name LIKE ?)`;
      whereClause += whereClause ? ` AND ${searchCondition}` : `WHERE ${searchCondition}`;
      const searchTerm = `%${search}%`;
      params.push(searchTerm, searchTerm, searchTerm);
    }
    
    const posts = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      ${whereClause}
      ORDER BY b.publishedAt DESC
      LIMIT ? OFFSET ?
    `).all(...params, parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total
      FROM blog_posts b
      LEFT JOIN users u ON u.id = b.authorId
      ${whereClause}
    `).get(...params);
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      posts,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalPosts: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).send({ error: 'Error fetching blog posts.' });
  }
});

app.get('/api/blog/categories', (req, res) => {
  try {
    const categories = db.prepare(`
      SELECT category, COUNT(*) as count 
      FROM blog_posts 
      WHERE isPublished = 1 
      GROUP BY category 
      ORDER BY count DESC
    `).all();
    res.send(categories);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching categories.' });
  }
});

app.get('/api/blog/:id', (req, res) => {
  try {
    const post = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(req.params.id);
    
    if (!post) {
      return res.status(404).send({ error: 'Blog post not found.' });
    }
    
    res.send(post);
  } catch (error) {
    console.error('Error fetching blog post:', error);
    res.status(500).send({ error: 'Error fetching blog post.' });
  }
});

app.post('/api/blog', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, content, category, isPublished = true } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    content = sanitizeInput(content);
    category = sanitizeInput(category);
    
    if (!title || !content || !category) {
      return res.status(400).send({ error: 'Title, content, and category are required.' });
    }
    
    if (title.length > 200) {
      return res.status(400).send({ error: 'Title is too long.' });
    }
    
    const excerpt = generateExcerpt(content);
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const info = db.prepare(`
      INSERT INTO blog_posts (title, content, excerpt, authorId, category, imageUrl, isPublished, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, content, excerpt, req.user.id, category, imageUrl, isPublished ? 1 : 0);
    
    const createdPost = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(info.lastInsertRowid);
    
    res.status(201).send(createdPost);
  } catch (error) {
    console.error('Error creating blog post:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error creating blog post.' });
  }
});

app.put('/api/blog/:id', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    const postId = req.params.id;
    const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(postId);
    
    if (!post) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (post.authorId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to update this post.' });
    }
    
    let { title, content, category, isPublished } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || post.title;
    content = sanitizeInput(content) || post.content;
    category = sanitizeInput(category) || post.category;
    
    if (title && title.length > 200) {
      return res.status(400).send({ error: 'Title is too long.' });
    }
    
    const excerpt = content ? generateExcerpt(content) : post.excerpt;
    let imageUrl = post.imageUrl;
    
    // Handle image update
    if (req.file) {
      // Delete old image if exists
      if (post.imageUrl) {
        deleteFile(post.imageUrl);
      }
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    db.prepare(`
      UPDATE blog_posts 
      SET title = ?, content = ?, excerpt = ?, category = ?, imageUrl = ?, isPublished = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      content, 
      excerpt, 
      category, 
      imageUrl, 
      isPublished !== undefined ? (isPublished ? 1 : 0) : post.isPublished,
      postId
    );
    
    const updatedPost = db.prepare(`
      SELECT b.*, u.name AS authorName
      FROM blog_posts b 
      LEFT JOIN users u ON u.id = b.authorId
      WHERE b.id = ?
    `).get(postId);
    
    res.send(updatedPost);
  } catch (error) {
    console.error('Error updating blog post:', error);
    
    // Clean up uploaded file if there was an error
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error updating blog post.' });
  }
});

app.delete('/api/blog/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const postId = req.params.id;
    const post = db.prepare('SELECT * FROM blog_posts WHERE id = ?').get(postId);
    
    if (!post) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (post.authorId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to delete this post.' });
    }
    
    // Delete associated image
    if (post.imageUrl) {
      deleteFile(post.imageUrl);
    }
    
    db.prepare('DELETE FROM blog_posts WHERE id = ?').run(postId);
    
    res.send({ message: 'Post deleted successfully.' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).send({ error: 'Error deleting post.' });
  }
});

// ------------------- EVENT ROUTES -------------------
app.get('/api/events', (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (upcoming) {
      whereClause = 'WHERE date >= date("now")';
    }
    
    const events = db.prepare(`
      SELECT * FROM events 
      ${whereClause}
      ORDER BY date ${upcoming ? 'ASC' : 'DESC'}
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM events ${whereClause}
    `).get();
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      events,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalEvents: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching events.' });
  }
});

app.get('/api/events/:id', (req, res) => {
  try {
    const event = db.prepare('SELECT * FROM events WHERE id = ?').get(req.params.id);
    if (!event) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    res.send(event);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching event.' });
  }
});

app.post('/api/events', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, description, date, location, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    
    if (!title || !description || !date || !location) {
      return res.status(400).send({ error: 'Title, description, date, and location are required.' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const info = db.prepare(`
      INSERT INTO events (title, description, date, location, imageUrl, registrationUrl, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, description, date, location, imageUrl, registrationUrl || null);
    
    const createdEvent = db.prepare('SELECT * FROM events WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(createdEvent);
  } catch (error) {
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    res.status(400).send({ error: 'Error creating event.' });
  }
});

// MISSING: PUT and DELETE routes for events
app.put('/api/events/:id', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    const eventId = req.params.id;
    const event = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);
    
    if (!event) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    
    let { title, description, date, location, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || event.title;
    description = sanitizeInput(description) || event.description;
    location = sanitizeInput(location) || event.location;
    
    let imageUrl = event.imageUrl;
    
    // Handle image update
    if (req.file) {
      // Delete old image if exists
      if (event.imageUrl) {
        deleteFile(event.imageUrl);
      }
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    db.prepare(`
      UPDATE events 
      SET title = ?, description = ?, date = ?, location = ?, imageUrl = ?, registrationUrl = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      description, 
      date || event.date, 
      location, 
      imageUrl, 
      registrationUrl || event.registrationUrl,
      eventId
    );
    
    const updatedEvent = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);
    res.send(updatedEvent);
  } catch (error) {
    console.error('Error updating event:', error);
    
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error updating event.' });
  }
});

app.delete('/api/events/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const eventId = req.params.id;
    const event = db.prepare('SELECT * FROM events WHERE id = ?').get(eventId);
    
    if (!event) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    
    // Delete associated image
    if (event.imageUrl) {
      deleteFile(event.imageUrl);
    }
    
    db.prepare('DELETE FROM events WHERE id = ?').run(eventId);
    
    res.send({ message: 'Event deleted successfully.' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).send({ error: 'Error deleting event.' });
  }
});

// ------------------- WORKSHOP ROUTES -------------------
app.get('/api/workshops', (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (upcoming) {
      whereClause = 'WHERE date >= date("now")';
    }
    
    const workshops = db.prepare(`
      SELECT * FROM workshops 
      ${whereClause}
      ORDER BY date ${upcoming ? 'ASC' : 'DESC'}
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM workshops ${whereClause}
    `).get();
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      workshops,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalWorkshops: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching workshops.' });
  }
});

app.get('/api/workshops/:id', (req, res) => {
  try {
    const workshop = db.prepare('SELECT * FROM workshops WHERE id = ?').get(req.params.id);
    if (!workshop) {
      return res.status(404).send({ error: 'Workshop not found.' });
    }
    res.send(workshop);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching workshop.' });
  }
});

app.post('/api/workshops', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, description, date, facilitator, location, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    facilitator = sanitizeInput(facilitator);
    
    if (!title || !description || !date || !location || !facilitator) {
      return res.status(400).send({ error: 'Title, description, date, location, and facilitator are required.' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    // FIXED: Added location to the INSERT query
    const info = db.prepare(`
      INSERT INTO workshops (title, description, date, facilitator, location, imageUrl, registrationUrl, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, description, date, facilitator, location, imageUrl, registrationUrl || null);
    
    const createdWorkshop = db.prepare('SELECT * FROM workshops WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(createdWorkshop);
  } catch (error) {
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    res.status(400).send({ error: 'Error creating workshop.' });
  }
});

// MISSING: PUT and DELETE routes for workshops
app.put('/api/workshops/:id', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    const workshopId = req.params.id;
    const workshop = db.prepare('SELECT * FROM workshops WHERE id = ?').get(workshopId);
    
    if (!workshop) {
      return res.status(404).send({ error: 'Workshop not found.' });
    }
    
    let { title, description, date, facilitator, location, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || workshop.title;
    description = sanitizeInput(description) || workshop.description;
    location = sanitizeInput(location) || workshop.location;
    facilitator = sanitizeInput(facilitator) || workshop.facilitator;
    
    let imageUrl = workshop.imageUrl;
    
    // Handle image update
    if (req.file) {
      // Delete old image if exists
      if (workshop.imageUrl) {
        deleteFile(workshop.imageUrl);
      }
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    db.prepare(`
      UPDATE workshops 
      SET title = ?, description = ?, date = ?, facilitator = ?, location = ?, imageUrl = ?, registrationUrl = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      description, 
      date || workshop.date, 
      facilitator, 
      location, 
      imageUrl, 
      registrationUrl || workshop.registrationUrl,
      workshopId
    );
    
    const updatedWorkshop = db.prepare('SELECT * FROM workshops WHERE id = ?').get(workshopId);
    res.send(updatedWorkshop);
  } catch (error) {
    console.error('Error updating workshop:', error);
    
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error updating workshop.' });
  }
});

app.delete('/api/workshops/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const workshopId = req.params.id;
    const workshop = db.prepare('SELECT * FROM workshops WHERE id = ?').get(workshopId);
    
    if (!workshop) {
      return res.status(404).send({ error: 'Workshop not found.' });
    }
    
    // Delete associated image
    if (workshop.imageUrl) {
      deleteFile(workshop.imageUrl);
    }
    
    db.prepare('DELETE FROM workshops WHERE id = ?').run(workshopId);
    
    res.send({ message: 'Workshop deleted successfully.' });
  } catch (error) {
    console.error('Error deleting workshop:', error);
    res.status(500).send({ error: 'Error deleting workshop.' });
  }
});

// ------------------- WEBINAR ROUTES -------------------
app.get('/api/webinars', (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (upcoming) {
      whereClause = 'WHERE date >= date("now")';
    }
    
    const webinars = db.prepare(`
      SELECT * FROM webinars 
      ${whereClause}
      ORDER BY date ${upcoming ? 'ASC' : 'DESC'}
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM webinars ${whereClause}
    `).get();
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      webinars,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalWebinars: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching webinars.' });
  }
});

app.get('/api/webinars/:id', (req, res) => {
  try {
    const webinar = db.prepare('SELECT * FROM webinars WHERE id = ?').get(req.params.id);
    if (!webinar) {
      return res.status(404).send({ error: 'Webinar not found.' });
    }
    res.send(webinar);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching webinar.' });
  }
});

app.post('/api/webinars', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    let { title, description, date, speaker, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    speaker = sanitizeInput(speaker);
    
    if (!title || !description || !date || !speaker) {
      return res.status(400).send({ error: 'Title, description, date, and speaker are required.' });
    }
    
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    
    const info = db.prepare(`
      INSERT INTO webinars (title, description, date, speaker, imageUrl, registrationUrl, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, description, date, speaker, imageUrl, registrationUrl || null);
    
    const createdWebinar = db.prepare('SELECT * FROM webinars WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(createdWebinar);
  } catch (error) {
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    res.status(400).send({ error: 'Error creating webinar.' });
  }
});

// MISSING: PUT and DELETE routes for webinars
app.put('/api/webinars/:id', authMiddleware, editorMiddleware, upload.single('image'), (req, res) => {
  try {
    const webinarId = req.params.id;
    const webinar = db.prepare('SELECT * FROM webinars WHERE id = ?').get(webinarId);
    
    if (!webinar) {
      return res.status(404).send({ error: 'Webinar not found.' });
    }
    
    let { title, description, date, speaker, registrationUrl } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || webinar.title;
    description = sanitizeInput(description) || webinar.description;
    speaker = sanitizeInput(speaker) || webinar.speaker;
    
    let imageUrl = webinar.imageUrl;
    
    // Handle image update
    if (req.file) {
      // Delete old image if exists
      if (webinar.imageUrl) {
        deleteFile(webinar.imageUrl);
      }
      imageUrl = `/uploads/${req.file.filename}`;
    }
    
    db.prepare(`
      UPDATE webinars 
      SET title = ?, description = ?, date = ?, speaker = ?, imageUrl = ?, registrationUrl = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      description, 
      date || webinar.date, 
      speaker, 
      imageUrl, 
      registrationUrl || webinar.registrationUrl,
      webinarId
    );
    
    const updatedWebinar = db.prepare('SELECT * FROM webinars WHERE id = ?').get(webinarId);
    res.send(updatedWebinar);
  } catch (error) {
    console.error('Error updating webinar:', error);
    
    if (req.file) {
      deleteFile(`/uploads/${req.file.filename}`);
    }
    
    res.status(400).send({ error: 'Error updating webinar.' });
  }
});

app.delete('/api/webinars/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const webinarId = req.params.id;
    const webinar = db.prepare('SELECT * FROM webinars WHERE id = ?').get(webinarId);
    
    if (!webinar) {
      return res.status(404).send({ error: 'Webinar not found.' });
    }
    
    // Delete associated image
    if (webinar.imageUrl) {
      deleteFile(webinar.imageUrl);
    }
    
    db.prepare('DELETE FROM webinars WHERE id = ?').run(webinarId);
    
    res.send({ message: 'Webinar deleted successfully.' });
  } catch (error) {
    console.error('Error deleting webinar:', error);
    res.status(500).send({ error: 'Error deleting webinar.' });
  }
});

// ------------------- CAREER ROUTES -------------------
app.get('/api/careers', (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    const careers = db.prepare(`
      SELECT * FROM careers 
      ORDER BY deadline DESC
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM careers
    `).get();
    
    const totalPages = Math.ceil(totalResult.total / parseInt(limit));
    
    res.send({
      careers,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalCareers: totalResult.total,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching careers.' });
  }
});

app.get('/api/careers/:id', (req, res) => {
  try {
    const career = db.prepare('SELECT * FROM careers WHERE id = ?').get(req.params.id);
    if (!career) {
      return res.status(404).send({ error: 'Career not found.' });
    }
    res.send(career);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching career.' });
  }
});

app.post('/api/careers', authMiddleware, editorMiddleware, (req, res) => {
  try {
    let { title, description, requirements, location, deadline } = req.body;
    
    // Input validation
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    
    if (!title || !description || !location || !deadline) {
      return res.status(400).send({ error: 'Title, description, location, and deadline are required.' });
    }
    
    const info = db.prepare(`
      INSERT INTO careers (title, description, requirements, location, deadline, updatedAt)
      VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).run(title, description, requirements || null, location, deadline);
    
    const createdCareer = db.prepare('SELECT * FROM careers WHERE id = ?').get(info.lastInsertRowid);
    res.status(201).send(createdCareer);
  } catch (error) {
    res.status(400).send({ error: 'Error posting career.' });
  }
});

// MISSING: PUT and DELETE routes for careers
app.put('/api/careers/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const careerId = req.params.id;
    const career = db.prepare('SELECT * FROM careers WHERE id = ?').get(careerId);
    
    if (!career) {
      return res.status(404).send({ error: 'Career not found.' });
    }
    
    let { title, description, requirements, location, deadline } = req.body;
    
    // Input validation
    title = sanitizeInput(title) || career.title;
    description = sanitizeInput(description) || career.description;
    location = sanitizeInput(location) || career.location;
    
    db.prepare(`
      UPDATE careers 
      SET title = ?, description = ?, requirements = ?, location = ?, deadline = ?, updatedAt = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(
      title, 
      description, 
      requirements || career.requirements,
      location, 
      deadline || career.deadline,
      careerId
    );
    
    const updatedCareer = db.prepare('SELECT * FROM careers WHERE id = ?').get(careerId);
    res.send(updatedCareer);
  } catch (error) {
    console.error('Error updating career:', error);
    res.status(400).send({ error: 'Error updating career.' });
  }
});

app.delete('/api/careers/:id', authMiddleware, editorMiddleware, (req, res) => {
  try {
    const careerId = req.params.id;
    const career = db.prepare('SELECT * FROM careers WHERE id = ?').get(careerId);
    
    if (!career) {
      return res.status(404).send({ error: 'Career not found.' });
    }
    
    db.prepare('DELETE FROM careers WHERE id = ?').run(careerId);
    
    res.send({ message: 'Career deleted successfully.' });
  } catch (error) {
    console.error('Error deleting career:', error);
    res.status(500).send({ error: 'Error deleting career.' });
  }
});

// ------------------- CONTACT ROUTES -------------------
app.post('/api/contact', (req, res) => {
  try {
    let { name, email, subject, message } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    subject = sanitizeInput(subject);
    message = sanitizeInput(message);
    
    if (!name || !email || !subject || !message) {
      return res.status(400).send({ error: 'All fields are required.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (name.length > 100) {
      return res.status(400).send({ error: 'Name is too long.' });
    }
    
    if (subject.length > 200) {
      return res.status(400).send({ error: 'Subject is too long.' });
    }
    
    db.prepare('INSERT INTO contact_forms (name, email, subject, message) VALUES (?, ?, ?, ?)')
      .run(name, email, subject, message);
    
    res.status(201).send({ message: 'Contact form submitted successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Error submitting contact form.' });
  }
});

// Admin contact management routes
app.get('/api/admin/contact', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { page = 1, limit = 20, unreadOnly = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (unreadOnly) {
      whereClause = 'WHERE isRead = 0';
    }
    
    const contacts = db.prepare(`
      SELECT * FROM contact_forms 
      ${whereClause}
      ORDER BY createdAt DESC
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM contact_forms ${whereClause}
    `).get();
    
    res.send({
      contacts,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalResult.total / parseInt(limit)),
        totalContacts: totalResult.total
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching contacts.' });
  }
});

app.put('/api/admin/contact/:id/mark-read', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const contactId = req.params.id;
    const contact = db.prepare('SELECT * FROM contact_forms WHERE id = ?').get(contactId);
    
    if (!contact) {
      return res.status(404).send({ error: 'Contact not found.' });
    }
    
    db.prepare('UPDATE contact_forms SET isRead = 1 WHERE id = ?').run(contactId);
    
    res.send({ message: 'Contact marked as read.' });
  } catch (error) {
    res.status(400).send({ error: 'Error updating contact.' });
  }
});

app.delete('/api/admin/contact/:id', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const contactId = req.params.id;
    const contact = db.prepare('SELECT * FROM contact_forms WHERE id = ?').get(contactId);
    
    if (!contact) {
      return res.status(404).send({ error: 'Contact not found.' });
    }
    
    db.prepare('DELETE FROM contact_forms WHERE id = ?').run(contactId);
    
    res.send({ message: 'Contact deleted successfully.' });
  } catch (error) {
    res.status(500).send({ error: 'Error deleting contact.' });
  }
});

// ------------------- NEWSLETTER ROUTES -------------------
app.post('/api/newsletter/subscribe', (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).send({ error: 'Valid email is required.' });
    }
    
    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email);
    if (existing) {
      if (!existing.isActive) {
        db.prepare('UPDATE newsletter_subscribers SET isActive = 1 WHERE email = ?').run(email);
        return res.send({ message: 'Resubscribed successfully.' });
      }
      return res.status(400).send({ error: 'Email already subscribed.' });
    }
    
    db.prepare('INSERT INTO newsletter_subscribers (email) VALUES (?)').run(email);
    res.status(201).send({ message: 'Subscribed successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Subscription failed.' });
  }
});

app.post('/api/newsletter/unsubscribe', (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).send({ error: 'Valid email is required.' });
    }
    
    const existing = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?').get(email);
    if (!existing) {
      return res.status(404).send({ error: 'Email not found in subscribers.' });
    }
    
    db.prepare('UPDATE newsletter_subscribers SET isActive = 0 WHERE email = ?').run(email);
    res.send({ message: 'Unsubscribed successfully.' });
  } catch (error) {
    res.status(400).send({ error: 'Unsubscribe failed.' });
  }
});

// ------------------- DONATION ROUTES -------------------
app.post('/api/donate', (req, res) => {
  try {
    let { name, email, amount, message, paymentMethod } = req.body;
    
    // Input validation
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    message = sanitizeInput(message);
    
    if (!name || !email || !amount || !paymentMethod) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (parseFloat(amount) <= 0) {
      return res.status(400).send({ error: 'Donation amount must be positive.' });
    }
    
    const info = db.prepare('INSERT INTO donations (name, email, amount, message, paymentMethod) VALUES (?, ?, ?, ?, ?)')
      .run(name, email, parseFloat(amount), message || null, paymentMethod);
    
    const donation = db.prepare('SELECT * FROM donations WHERE id = ?').get(info.lastInsertRowid);
    
    res.status(201).send({ 
      message: 'Donation recorded successfully.',
      donation
    });
  } catch (error) {
    res.status(400).send({ error: 'Error processing donation.' });
  }
});

// Admin donation management
app.get('/api/admin/donations', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { page = 1, limit = 20, processedOnly } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let whereClause = '';
    if (processedOnly === 'true') {
      whereClause = 'WHERE isProcessed = 1';
    } else if (processedOnly === 'false') {
      whereClause = 'WHERE isProcessed = 0';
    }
    
    const donations = db.prepare(`
      SELECT * FROM donations 
      ${whereClause}
      ORDER BY createdAt DESC
      LIMIT ? OFFSET ?
    `).all(parseInt(limit), offset);
    
    const totalResult = db.prepare(`
      SELECT COUNT(*) as total FROM donations ${whereClause}
    `).get();
    
    res.send({
      donations,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalResult.total / parseInt(limit)),
        totalDonations: totalResult.total
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching donations.' });
  }
});

app.put('/api/admin/donations/:id/process', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const donationId = req.params.id;
    const donation = db.prepare('SELECT * FROM donations WHERE id = ?').get(donationId);
    
    if (!donation) {
      return res.status(404).send({ error: 'Donation not found.' });
    }
    
    db.prepare('UPDATE donations SET isProcessed = 1 WHERE id = ?').run(donationId);
    
    res.send({ message: 'Donation marked as processed.' });
  } catch (error) {
    res.status(400).send({ error: 'Error processing donation.' });
  }
});

// ------------------- ADMIN DASHBOARD -------------------
app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const q = (sql) => db.prepare(sql).get();
    const stats = {
      blogPostsCount: q('SELECT COUNT(*) AS c FROM blog_posts').c,
      eventsCount: q('SELECT COUNT(*) AS c FROM events').c,
      workshopsCount: q('SELECT COUNT(*) AS c FROM workshops').c,
      webinarsCount: q('SELECT COUNT(*) AS c FROM webinars').c,
      careerCount: q('SELECT COUNT(*) AS c FROM careers').c,
      contactFormsCount: q('SELECT COUNT(*) AS c FROM contact_forms').c,
      subscribersCount: q('SELECT COUNT(*) AS c FROM newsletter_subscribers WHERE isActive = 1').c,
      donationsCount: q('SELECT COUNT(*) AS c FROM donations').c,
      totalDonations: q('SELECT COALESCE(SUM(amount), 0) AS total FROM donations').total,
      unreadContacts: q('SELECT COUNT(*) AS c FROM contact_forms WHERE isRead = 0').c,
      unprocessedDonations: q('SELECT COUNT(*) AS c FROM donations WHERE isProcessed = 0').c,
      recentActivities: db.prepare(`
        SELECT 'blog' as type, title, publishedAt as date FROM blog_posts 
        UNION SELECT 'event' as type, title, createdAt as date FROM events
        UNION SELECT 'donation' as type, name || ' - $' || amount as title, createdAt as date FROM donations
        ORDER BY date DESC LIMIT 10
      `).all()
    };
    res.send(stats);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching stats.' });
  }
});

// ------------------- ROOT ENDPOINT -------------------
app.get('/', (req, res) => {
  res.json({
    message: 'Radiant Hope Media API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth',
      blog: '/api/blog',
      events: '/api/events',
      workshops: '/api/workshops',
      webinars: '/api/webinars',
      careers: '/api/careers',
      contact: '/api/contact',
      newsletter: '/api/newsletter',
      donate: '/api/donate',
      admin: '/api/admin',
      health: '/api/health'
    }
  });
});

// ------------------- ERROR HANDLING -------------------
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).send({ error: 'File too large. Maximum size is 5MB.' });
    }
  }
  
  console.error('Unhandled error:', error?.message || error);
  res.status(500).send({ error: 'Something went wrong!' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).send({ error: 'Endpoint not found.' });
});

// ------------------- EXPORT APP FOR DEPLOYMENT -------------------
export { app };

// ------------------- SERVER START (optional) -------------------
if (process.env.RUN_SERVER !== 'false') {
  const PORT = process.env.PORT || 5000;
  const server = app.listen(PORT, () => {
    console.log(`\n🎉 Radiant Hope Media API Server Started!\n`);
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`✅ Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`\n📚 API Documentation:`);
    console.log(`   🌐 API Base URL: http://localhost:${PORT}/`);
    console.log(`   🩺 Health Check: http://localhost:${PORT}/api/health`);
    console.log(`\n🚀 Ready to accept requests!`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    server.close(() => {
      console.log('Server closed.');
      process.exit(0);
    });
  });
}