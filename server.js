import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';

// ------------------- SUPABASE SETUP -------------------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('❌ SUPABASE_URL and SUPABASE_ANON_KEY are required');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseKey);

// ------------------- APP & MIDDLEWARE -------------------
const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || '100'),
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// CORS setup
const rawOrigins = process.env.CORS_ORIGIN || '*';
const allowedOrigins = rawOrigins.split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy: Origin not allowed'));
  },
  credentials: true,
  methods: ['GET','HEAD','PUT','PATCH','POST','DELETE'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

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

const generateExcerpt = (content, maxLength = 150) => {
  const plainText = content.replace(/<[^>]*>/g, '');
  return plainText.length > maxLength 
    ? plainText.substring(0, maxLength) + '...' 
    : plainText;
};

// ------------------- AUTH HELPERS -------------------
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).send({ error: 'Access denied. No token provided.' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', decoded.id)
      .single();
    
    if (error || !user) {
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

// ------------------- INITIALIZE DATABASE -------------------
const initDatabase = async () => {
  try {
    // Create tables if they don't exist
    const tablesSQL = `
      -- Users table
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'editor',
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Blog posts table
      CREATE TABLE IF NOT EXISTS blog_posts (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        excerpt TEXT,
        author_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        category TEXT NOT NULL,
        image_url TEXT,
        published_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW(),
        is_published BOOLEAN DEFAULT true
      );
      
      -- Events table
      CREATE TABLE IF NOT EXISTS events (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        date TEXT NOT NULL,
        location TEXT NOT NULL,
        image_url TEXT,
        registration_url TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Workshops table
      CREATE TABLE IF NOT EXISTS workshops (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        date TEXT NOT NULL,
        facilitator TEXT NOT NULL,
        location TEXT NOT NULL,
        image_url TEXT,
        registration_url TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Webinars table
      CREATE TABLE IF NOT EXISTS webinars (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        date TEXT NOT NULL,
        speaker TEXT NOT NULL,
        image_url TEXT,
        registration_url TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Careers table
      CREATE TABLE IF NOT EXISTS careers (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        requirements TEXT,
        location TEXT NOT NULL,
        deadline TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Contact forms table
      CREATE TABLE IF NOT EXISTS contact_forms (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Newsletter subscribers table
      CREATE TABLE IF NOT EXISTS newsletter_subscribers (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT true,
        subscribed_at TIMESTAMP DEFAULT NOW()
      );
      
      -- Donations table
      CREATE TABLE IF NOT EXISTS donations (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        message TEXT,
        payment_method TEXT NOT NULL,
        is_processed BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `;
    
    // Execute SQL using Supabase
    await supabase.rpc('exec_sql', { sql: tablesSQL }).catch(() => {});
    
    // Check for admin user
    const { data: admin } = await supabase
      .from('users')
      .select('*')
      .eq('email', 'admin@radianthope.com')
      .single();
    
    if (!admin && process.env.CREATE_DEFAULT_ADMIN !== 'false') {
      const hashedPassword = bcrypt.hashSync(process.env.DEFAULT_ADMIN_PWD || 'admin123', 10);
      await supabase.from('users').insert({
        name: 'Admin User',
        email: 'admin@radianthope.com',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('✅ Default admin user created');
    }
    
    console.log('✅ Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
};

// Initialize database on startup
initDatabase();

// ------------------- HEALTH CHECK -------------------
app.get('/api/health', async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('count').limit(1);
    
    res.send({
      status: 'ok',
      database: !error,
      time: new Date().toISOString(),
      version: '1.0.0',
      supabase: true
    });
  } catch (err) {
    res.status(500).send({ status: 'error', error: 'Database check failed' });
  }
});

// ------------------- ROOT ENDPOINT -------------------
app.get('/', (req, res) => {
  res.json({
    message: 'Radiant Hope Media API',
    version: '1.0.0',
    database: 'Supabase PostgreSQL',
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

// ------------------- AUTH ROUTES -------------------
app.post('/api/auth/register', async (req, res) => {
  try {
    let { name, email, password, role = 'editor' } = req.body;
    
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    
    if (!name || !email || !password) {
      return res.status(400).send({ error: 'Name, email, and password are required.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    if (password.length < 6) {
      return res.status(400).send({ error: 'Password must be at least 6 characters.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const { data: user, error } = await supabase
      .from('users')
      .insert({
        name,
        email,
        password: hashedPassword,
        role
      })
      .select()
      .single();
    
    if (error) {
      if (error.code === '23505') {
        return res.status(400).send({ error: 'Email already exists.' });
      }
      throw error;
    }
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).send({ 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      }, 
      token 
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(400).send({ error: 'Registration failed.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).send({ error: 'Email and password are required.' });
    }
    
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();
    
    if (error || !user) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send({ error: 'Invalid login credentials.' });
    }
    
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.send({ 
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      }, 
      token 
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).send({ error: 'Login failed.' });
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { password, ...safeUser } = req.user;
  res.send(safeUser);
});

// ------------------- BLOG ROUTES -------------------
app.get('/api/blog', async (req, res) => {
  try {
    const { page = 1, limit = 10, category, search, publishedOnly = true } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('blog_posts')
      .select(`
        *,
        users:author_id (name)
      `, { count: 'exact' });
    
    if (publishedOnly) {
      query = query.eq('is_published', true);
    }
    
    if (category) {
      query = query.eq('category', category);
    }
    
    if (search) {
      query = query.or(`title.ilike.%${search}%,content.ilike.%${search}%`);
    }
    
    query = query.order('published_at', { ascending: false })
      .range(offset, offset + parseInt(limit) - 1);
    
    const { data: posts, error, count } = await query;
    
    if (error) throw error;
    
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.send({
      posts: posts.map(post => ({
        ...post,
        authorName: post.users?.name
      })),
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalPosts: count,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    console.error('Error fetching blog posts:', error);
    res.status(500).send({ error: 'Error fetching blog posts.' });
  }
});

app.get('/api/blog/categories', async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('blog_posts')
      .select('category')
      .eq('is_published', true);
    
    if (error) throw error;
    
    const categories = data.reduce((acc, post) => {
      acc[post.category] = (acc[post.category] || 0) + 1;
      return acc;
    }, {});
    
    const result = Object.entries(categories).map(([category, count]) => ({
      category,
      count
    }));
    
    res.send(result);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching categories.' });
  }
});

app.get('/api/blog/:id', async (req, res) => {
  try {
    const { data: post, error } = await supabase
      .from('blog_posts')
      .select(`
        *,
        users:author_id (name)
      `)
      .eq('id', req.params.id)
      .single();
    
    if (error || !post) {
      return res.status(404).send({ error: 'Blog post not found.' });
    }
    
    res.send({
      ...post,
      authorName: post.users?.name
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching blog post.' });
  }
});

app.post('/api/blog', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    let { title, content, category, isPublished = true, imageUrl } = req.body;
    
    title = sanitizeInput(title);
    content = sanitizeInput(content);
    category = sanitizeInput(category);
    
    if (!title || !content || !category) {
      return res.status(400).send({ error: 'Title, content, and category are required.' });
    }
    
    const excerpt = generateExcerpt(content);
    
    const { data: post, error } = await supabase
      .from('blog_posts')
      .insert({
        title,
        content,
        excerpt,
        author_id: req.user.id,
        category,
        image_url: imageUrl,
        is_published: isPublished,
        updated_at: new Date().toISOString()
      })
      .select(`
        *,
        users:author_id (name)
      `)
      .single();
    
    if (error) throw error;
    
    res.status(201).send({
      ...post,
      authorName: post.users?.name
    });
  } catch (error) {
    console.error('Error creating blog post:', error);
    res.status(400).send({ error: 'Error creating blog post.' });
  }
});

app.put('/api/blog/:id', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check if post exists
    const { data: existingPost, error: fetchError } = await supabase
      .from('blog_posts')
      .select('*')
      .eq('id', postId)
      .single();
    
    if (fetchError || !existingPost) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (existingPost.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to update this post.' });
    }
    
    let { title, content, category, isPublished, imageUrl } = req.body;
    
    const updates = {
      updated_at: new Date().toISOString()
    };
    
    if (title !== undefined) updates.title = sanitizeInput(title);
    if (content !== undefined) {
      updates.content = sanitizeInput(content);
      updates.excerpt = generateExcerpt(content);
    }
    if (category !== undefined) updates.category = sanitizeInput(category);
    if (isPublished !== undefined) updates.is_published = isPublished;
    if (imageUrl !== undefined) updates.image_url = imageUrl;
    
    const { data: post, error } = await supabase
      .from('blog_posts')
      .update(updates)
      .eq('id', postId)
      .select(`
        *,
        users:author_id (name)
      `)
      .single();
    
    if (error) throw error;
    
    res.send({
      ...post,
      authorName: post.users?.name
    });
  } catch (error) {
    console.error('Error updating blog post:', error);
    res.status(400).send({ error: 'Error updating blog post.' });
  }
});

app.delete('/api/blog/:id', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    const postId = req.params.id;
    
    // Check if post exists
    const { data: existingPost, error: fetchError } = await supabase
      .from('blog_posts')
      .select('*')
      .eq('id', postId)
      .single();
    
    if (fetchError || !existingPost) {
      return res.status(404).send({ error: 'Post not found.' });
    }
    
    // Check authorization
    if (existingPost.author_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).send({ error: 'Not authorized to delete this post.' });
    }
    
    const { error } = await supabase
      .from('blog_posts')
      .delete()
      .eq('id', postId);
    
    if (error) throw error;
    
    res.send({ message: 'Post deleted successfully.' });
  } catch (error) {
    console.error('Error deleting blog post:', error);
    res.status(500).send({ error: 'Error deleting post.' });
  }
});

// ------------------- EVENT ROUTES -------------------
app.get('/api/events', async (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('events')
      .select('*', { count: 'exact' });
    
    if (upcoming) {
      query = query.gte('date', new Date().toISOString().split('T')[0]);
    }
    
    query = query.order('date', { ascending: upcoming })
      .range(offset, offset + parseInt(limit) - 1);
    
    const { data: events, error, count } = await query;
    
    if (error) throw error;
    
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.send({
      events,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalEvents: count,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching events.' });
  }
});

app.get('/api/events/:id', async (req, res) => {
  try {
    const { data: event, error } = await supabase
      .from('events')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (error || !event) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    res.send(event);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching event.' });
  }
});

app.post('/api/events', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    let { title, description, date, location, registrationUrl, imageUrl } = req.body;
    
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    
    if (!title || !description || !date || !location) {
      return res.status(400).send({ error: 'Title, description, date, and location are required.' });
    }
    
    const { data: event, error } = await supabase
      .from('events')
      .insert({
        title,
        description,
        date,
        location,
        image_url: imageUrl,
        registration_url: registrationUrl,
        updated_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send(event);
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(400).send({ error: 'Error creating event.' });
  }
});

app.put('/api/events/:id', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    const eventId = req.params.id;
    
    const { data: existingEvent, error: fetchError } = await supabase
      .from('events')
      .select('*')
      .eq('id', eventId)
      .single();
    
    if (fetchError || !existingEvent) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    
    let { title, description, date, location, registrationUrl, imageUrl } = req.body;
    
    const updates = {
      updated_at: new Date().toISOString()
    };
    
    if (title !== undefined) updates.title = sanitizeInput(title);
    if (description !== undefined) updates.description = sanitizeInput(description);
    if (date !== undefined) updates.date = date;
    if (location !== undefined) updates.location = sanitizeInput(location);
    if (registrationUrl !== undefined) updates.registration_url = registrationUrl;
    if (imageUrl !== undefined) updates.image_url = imageUrl;
    
    const { data: event, error } = await supabase
      .from('events')
      .update(updates)
      .eq('id', eventId)
      .select()
      .single();
    
    if (error) throw error;
    
    res.send(event);
  } catch (error) {
    console.error('Error updating event:', error);
    res.status(400).send({ error: 'Error updating event.' });
  }
});

app.delete('/api/events/:id', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    const eventId = req.params.id;
    
    const { data: existingEvent, error: fetchError } = await supabase
      .from('events')
      .select('*')
      .eq('id', eventId)
      .single();
    
    if (fetchError || !existingEvent) {
      return res.status(404).send({ error: 'Event not found.' });
    }
    
    const { error } = await supabase
      .from('events')
      .delete()
      .eq('id', eventId);
    
    if (error) throw error;
    
    res.send({ message: 'Event deleted successfully.' });
  } catch (error) {
    console.error('Error deleting event:', error);
    res.status(500).send({ error: 'Error deleting event.' });
  }
});

// ------------------- WORKSHOP ROUTES -------------------
app.get('/api/workshops', async (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('workshops')
      .select('*', { count: 'exact' });
    
    if (upcoming) {
      query = query.gte('date', new Date().toISOString().split('T')[0]);
    }
    
    query = query.order('date', { ascending: upcoming })
      .range(offset, offset + parseInt(limit) - 1);
    
    const { data: workshops, error, count } = await query;
    
    if (error) throw error;
    
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.send({
      workshops,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalWorkshops: count,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching workshops.' });
  }
});

app.get('/api/workshops/:id', async (req, res) => {
  try {
    const { data: workshop, error } = await supabase
      .from('workshops')
      .select('*')
      .eq('id', req.params.id)
      .single();
    
    if (error || !workshop) {
      return res.status(404).send({ error: 'Workshop not found.' });
    }
    res.send(workshop);
  } catch (error) {
    res.status(500).send({ error: 'Error fetching workshop.' });
  }
});

app.post('/api/workshops', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    let { title, description, date, facilitator, location, registrationUrl, imageUrl } = req.body;
    
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    facilitator = sanitizeInput(facilitator);
    
    if (!title || !description || !date || !location || !facilitator) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    const { data: workshop, error } = await supabase
      .from('workshops')
      .insert({
        title,
        description,
        date,
        facilitator,
        location,
        image_url: imageUrl,
        registration_url: registrationUrl,
        updated_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send(workshop);
  } catch (error) {
    console.error('Error creating workshop:', error);
    res.status(400).send({ error: 'Error creating workshop.' });
  }
});

// ------------------- WEBINAR ROUTES -------------------
app.get('/api/webinars', async (req, res) => {
  try {
    const { page = 1, limit = 10, upcoming = false } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    let query = supabase
      .from('webinars')
      .select('*', { count: 'exact' });
    
    if (upcoming) {
      query = query.gte('date', new Date().toISOString().split('T')[0]);
    }
    
    query = query.order('date', { ascending: upcoming })
      .range(offset, offset + parseInt(limit) - 1);
    
    const { data: webinars, error, count } = await query;
    
    if (error) throw error;
    
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.send({
      webinars,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalWebinars: count,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching webinars.' });
  }
});

app.post('/api/webinars', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    let { title, description, date, speaker, registrationUrl, imageUrl } = req.body;
    
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    speaker = sanitizeInput(speaker);
    
    if (!title || !description || !date || !speaker) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    const { data: webinar, error } = await supabase
      .from('webinars')
      .insert({
        title,
        description,
        date,
        speaker,
        image_url: imageUrl,
        registration_url: registrationUrl,
        updated_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send(webinar);
  } catch (error) {
    console.error('Error creating webinar:', error);
    res.status(400).send({ error: 'Error creating webinar.' });
  }
});

// ------------------- CAREER ROUTES -------------------
app.get('/api/careers', async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const offset = (parseInt(page) - 1) * parseInt(limit);
    
    const { data: careers, error, count } = await supabase
      .from('careers')
      .select('*', { count: 'exact' })
      .order('deadline', { ascending: true })
      .range(offset, offset + parseInt(limit) - 1);
    
    if (error) throw error;
    
    const totalPages = Math.ceil(count / parseInt(limit));
    
    res.send({
      careers,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalCareers: count,
        hasNext: parseInt(page) < totalPages,
        hasPrev: parseInt(page) > 1
      }
    });
  } catch (error) {
    res.status(500).send({ error: 'Error fetching careers.' });
  }
});

app.post('/api/careers', authMiddleware, editorMiddleware, async (req, res) => {
  try {
    let { title, description, requirements, location, deadline } = req.body;
    
    title = sanitizeInput(title);
    description = sanitizeInput(description);
    location = sanitizeInput(location);
    
    if (!title || !description || !location || !deadline) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    const { data: career, error } = await supabase
      .from('careers')
      .insert({
        title,
        description,
        requirements,
        location,
        deadline,
        updated_at: new Date().toISOString()
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send(career);
  } catch (error) {
    console.error('Error creating career:', error);
    res.status(400).send({ error: 'Error creating career.' });
  }
});

// ------------------- CONTACT ROUTES -------------------
app.post('/api/contact', async (req, res) => {
  try {
    let { name, email, subject, message } = req.body;
    
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
    
    const { data: contact, error } = await supabase
      .from('contact_forms')
      .insert({
        name,
        email,
        subject,
        message
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send({ 
      message: 'Contact form submitted successfully.',
      id: contact.id
    });
  } catch (error) {
    console.error('Error submitting contact form:', error);
    res.status(400).send({ error: 'Error submitting contact form.' });
  }
});

// ------------------- NEWSLETTER ROUTES -------------------
app.post('/api/newsletter/subscribe', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email || !validateEmail(email)) {
      return res.status(400).send({ error: 'Valid email is required.' });
    }
    
    // Check if already subscribed
    const { data: existing } = await supabase
      .from('newsletter_subscribers')
      .select('*')
      .eq('email', email)
      .single();
    
    if (existing) {
      if (!existing.is_active) {
        await supabase
          .from('newsletter_subscribers')
          .update({ is_active: true })
          .eq('email', email);
        return res.send({ message: 'Resubscribed successfully.' });
      }
      return res.status(400).send({ error: 'Email already subscribed.' });
    }
    
    const { data: subscriber, error } = await supabase
      .from('newsletter_subscribers')
      .insert({ email })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send({ message: 'Subscribed successfully.' });
  } catch (error) {
    console.error('Error subscribing:', error);
    res.status(400).send({ error: 'Subscription failed.' });
  }
});

// ------------------- DONATION ROUTES -------------------
app.post('/api/donate', async (req, res) => {
  try {
    let { name, email, amount, message, paymentMethod } = req.body;
    
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    message = sanitizeInput(message);
    
    if (!name || !email || !amount || !paymentMethod) {
      return res.status(400).send({ error: 'All required fields must be filled.' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).send({ error: 'Invalid email format.' });
    }
    
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      return res.status(400).send({ error: 'Invalid donation amount.' });
    }
    
    const { data: donation, error } = await supabase
      .from('donations')
      .insert({
        name,
        email,
        amount: amountNum,
        message,
        payment_method: paymentMethod
      })
      .select()
      .single();
    
    if (error) throw error;
    
    res.status(201).send({ 
      message: 'Donation recorded successfully.',
      donation
    });
  } catch (error) {
    console.error('Error processing donation:', error);
    res.status(400).send({ error: 'Error processing donation.' });
  }
});

// ------------------- ADMIN DASHBOARD -------------------
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    // Get counts from all tables
    const [
      blogPostsCount,
      eventsCount,
      workshopsCount,
      webinarsCount,
      careerCount,
      contactFormsCount,
      subscribersCount,
      donationsCount,
      totalDonations,
      unreadContacts,
      unprocessedDonations
    ] = await Promise.all([
      supabase.from('blog_posts').select('*', { count: 'exact', head: true }),
      supabase.from('events').select('*', { count: 'exact', head: true }),
      supabase.from('workshops').select('*', { count: 'exact', head: true }),
      supabase.from('webinars').select('*', { count: 'exact', head: true }),
      supabase.from('careers').select('*', { count: 'exact', head: true }),
      supabase.from('contact_forms').select('*', { count: 'exact', head: true }),
      supabase.from('newsletter_subscribers').select('*', { count: 'exact', head: true }).eq('is_active', true),
      supabase.from('donations').select('*', { count: 'exact', head: true }),
      supabase.from('donations').select('amount').then(({ data }) => 
        data.reduce((sum, donation) => sum + parseFloat(donation.amount), 0)
      ),
      supabase.from('contact_forms').select('*', { count: 'exact', head: true }).eq('is_read', false),
      supabase.from('donations').select('*', { count: 'exact', head: true }).eq('is_processed', false)
    ]);
    
    res.send({
      blogPostsCount: blogPostsCount.count || 0,
      eventsCount: eventsCount.count || 0,
      workshopsCount: workshopsCount.count || 0,
      webinarsCount: webinarsCount.count || 0,
      careerCount: careerCount.count || 0,
      contactFormsCount: contactFormsCount.count || 0,
      subscribersCount: subscribersCount.count || 0,
      donationsCount: donationsCount.count || 0,
      totalDonations: totalDonations || 0,
      unreadContacts: unreadContacts.count || 0,
      unprocessedDonations: unprocessedDonations.count || 0
    });
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).send({ error: 'Error fetching stats.' });
  }
});

// ------------------- ERROR HANDLING -------------------
app.use((error, req, res, next) => {
  console.error('Server Error:', error);
  res.status(500).send({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).send({ error: 'Endpoint not found.' });
});

// ------------------- EXPORT FOR VERCEL -------------------
export default app;