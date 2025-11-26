/**
 * index.js
 * Single-file Node + Express app (Write-Commune / LinkedIn-like UI)
 *
 * Features:
 * - Register (with optional profile photo upload)
 * - Login (returns JWT)
 * - Create posts (authenticated)
 * - Get posts (feed)
 * - Simple LinkedIn-like frontend (served by server)
 *
 * NOTE: For production, move secret and DB URI to environment variables.
 */

require("dotenv").config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_real_secret_in_prod';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/mynewproject';

// --- Setup uploads directory ---
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

// --- Multer storage for profile photos ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${unique}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } }); // 5MB limit

// --- Mongoose models ---
mongoose.set('strictQuery', true);
async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log("✅ MongoDB connected");
  } catch (err) {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  }
}

connectDB();

  
const { Schema } = mongoose;

const userSchema = new Schema({
  username: { type: String, required: true },
  email:    { type: String, required: true, unique: true },
  password: { type: String, required: true },
  photo:    { type: String, default: '' } // stores filename under uploads/
}, { timestamps: true });

const postSchema = new Schema({
  author:   { type: Schema.Types.ObjectId, ref: 'User' },
  title:    { type: String, default: '' },
  content:  { type: String, required: true },
  createdAt:{ type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Post = mongoose.model('Post', postSchema);

// --- Middleware ---
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR)); // serve uploaded files

// --- Default avatar route (SVG) ---
app.get('/avatar/default', (req, res) => {
  const svg = `
    <svg xmlns='http://www.w3.org/2000/svg' width='256' height='256' viewBox='0 0 24 24'>
      <rect width='100%' height='100%' fill='#0073b1'/>
      <g fill='#fff' transform='translate(4 3)'>
        <circle cx='8' cy='5' r='3'/>
        <path d='M0 17c0-3 4-5 8-5s8 2 8 5v1H0v-1z'/>
      </g>
    </svg>`;
  res.type('image/svg+xml').send(svg);
});

// --- Helpers ---
function generateToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}
async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Missing authorization header' });
  const token = header.startsWith('Bearer ') ? header.slice(7) : header;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    if (!req.user) return res.status(401).json({ error: 'Invalid token (user not found)' });
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// --- API routes ---

/**
 * Register
 * Accepts multipart/form-data to allow profile photo upload during signup
 * Fields: username, email, password, (optional) photo
 */
app.post('/api/register', upload.single('photo'), async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ error: 'username, email, password required' });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const hashed = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashed,
      photo: req.file ? req.file.filename : ''
    });

    await user.save();
    const token = generateToken(user);
    res.json({ message: 'User created', token, user: { id: user._id, username: user.username, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/**
 * Login
 * JSON body: { email, password }
 * Returns: { token, user }
 */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email, password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

    const token = generateToken(user);
    res.json({ message: 'Logged in', token, user: { id: user._id, username: user.username, email: user.email, photo: user.photo } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/**
 * Create Post (authenticated)
 * JSON body: { content, title? }
 */
app.post('/api/posts', authMiddleware, async (req, res) => {
  try {
    const { content, title } = req.body;
    if (!content) return res.status(400).json({ error: 'content required' });

    const post = new Post({
      author: req.user._id,
      title: title || '',
      content
    });
    await post.save();

    res.json({ message: 'Post created', post });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error creating post' });
  }
});

/**
 * Get Posts (feed)
 * Returns posts with author username and photo
 */
app.get('/api/posts', async (req, res) => {
  try {
    const posts = await Post.find()
      .sort({ createdAt: -1 })
      .limit(100)
      .populate('author', 'username photo');
    res.json(posts);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error fetching posts' });
  }
});

/**
 * Get user by id (used by frontend)
 */
app.get('/api/users/:id', async (req, res) => {
  try {
    const u = await User.findById(req.params.id).select('username email photo');
    if (!u) return res.status(404).json({ error: 'User not found' });
    res.json(u);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Frontend: Minimal LinkedIn-like pages served by server ---
// Serve static assets (we will inline CSS/JS into HTML below to keep single-file)
app.get('/', (req, res) => {
  res.send(mainPageHTML());
});
app.get('/feed', (req, res) => {
  res.send(feedPageHTML());
});



// routes here...



// --- Start server ---
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

// --- HTML helper functions (kept inline so index.js is self-contained) ---

function mainPageHTML() {
  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Write-Commune — Login / Signup</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    /* Simple LinkedIn-like styling (blue header, professional card) */
    :root{--blue:#0073b1;--muted:#6b7280;--card:#fff;--bg:#f3f4f6}
    body{font-family:Inter,system-ui,Arial,Helvetica,sans-serif;background:var(--bg);margin:0}
    header{background:linear-gradient(0deg,#006696, #0073b1);color:white;padding:18px 24px;display:flex;align-items:center;gap:16px}
    .brand{font-weight:700;font-size:18px}
    .container{max-width:980px;margin:28px auto;padding:16px}
    .card{background:var(--card);border-radius:8px;padding:20px;box-shadow:0 6px 18px rgba(0,0,0,0.08)}
    .grid{display:grid;grid-template-columns:1fr 420px;gap:20px}
    h2{margin:0 0 12px 0}
    label{display:block;font-weight:600;margin-bottom:6px}
    input[type=text],input[type=email],input[type=password],textarea{width:100%;padding:10px;border-radius:6px;border:1px solid #e5e7eb}
    button{background:var(--blue);color:white;padding:10px 14px;border-radius:6px;border:0;cursor:pointer}
    .muted{color:var(--muted);font-size:14px}
    .small{font-size:13px}
    .center{display:flex;gap:12px;align-items:center}
    .profile-preview{width:72px;height:72px;border-radius:8px;overflow:hidden;background:#ddd;display:flex;align-items:center;justify-content:center;color:#fff}
    .link{color:var(--blue);text-decoration:none;font-weight:600}
    footer{max-width:980px;margin:20px auto;color:var(--muted);font-size:13px}
  </style>
</head>
<body>
  <header>
    <div style="display:flex;align-items:center;gap:12px">
      <svg width="36" height="36" viewBox="0 0 24 24"><rect fill="#fff" rx="4" width="24" height="24"/><path d="M3 17v1a2 2 0 0 0 2 2h14" fill="#0073b1"/></svg>
      <div class="brand">Write-Commune</div>
    </div>
  </header>

  <div class="container">
    <div class="grid">
      <div>
        <div class="card">
          <h2>Welcome back</h2>
          <p class="muted">A professional place to share your thoughts — login to continue.</p>

          <div style="margin-top:16px">
            <label>Email</label>
            <input id="loginEmail" type="email" />
            <label style="margin-top:8px">Password</label>
            <input id="loginPassword" type="password" />
            <div style="margin-top:12px;display:flex;gap:8px">
              <button id="loginBtn">Sign in</button>
              <a href="#" id="gotoSignup" class="small muted" style="align-self:center">Create account</a>
            </div>
            <p id="loginMsg" class="muted small" style="margin-top:8px"></p>
          </div>
        </div>

        <div style="height:16px"></div>

        <div class="card">
          <h2>About</h2>
          <p class="muted">This demo lets users sign up (optionally upload a profile photo) and post text content. It mimics LinkedIn's clean, professional feed look.</p>
        </div>
      </div>

      <div>
        <div class="card">
          <h2>Create account</h2>
          <p class="muted small">Sign up with your details. You may upload a profile photo (optional).</p>

          <form id="signupForm" enctype="multipart/form-data">
            <label>Full name</label>
            <input name="username" required />
            <label style="margin-top:8px">Email</label>
            <input name="email" type="email" required />
            <label style="margin-top:8px">Password</label>
            <input name="password" type="password" required />
            <label style="margin-top:8px">Profile photo (optional)</label>
            <input name="photo" type="file" accept="image/*" />
            <div style="margin-top:10px">
              <button type="submit">Create account</button>
            </div>
            <p id="signupMsg" class="muted small" style="margin-top:8px"></p>
          </form>
        </div>

        <div style="height:16px"></div>

        <div class="card">
          <h3>Need help?</h3>
          <p class="muted small">If you face issues, open the browser console to see request errors.</p>
          <p style="margin-top:8px"><a class="link" href="/feed">Go to feed (demo)</a></p>
        </div>

      </div>
    </div>
  </div>

  <footer>
    <div class="container">Made for learning — not for production. Use strong secrets & HTTPS in production.</div>
  </footer>

  <script>
    // Login
    document.getElementById('loginBtn').onclick = async () => {
      const email = document.getElementById('loginEmail').value;
      const password = document.getElementById('loginPassword').value;
      const msg = document.getElementById('loginMsg');
      msg.textContent = '';
      try {
        const res = await fetch('/api/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
        const data = await res.json();
        if (!res.ok) { msg.textContent = data.error || 'Login failed'; return; }
        localStorage.setItem('token', data.token);
        // redirect to feed
        location.href = '/feed';
      } catch (err) {
        msg.textContent = 'Network error';
      }
    };

    // Signup
    document.getElementById('signupForm').onsubmit = async (e) => {
      e.preventDefault();
      const msg = document.getElementById('signupMsg');
      msg.textContent = 'Creating...';
      const form = e.target;
      const formData = new FormData(form);
      try {
        const res = await fetch('/api/register', { method:'POST', body: formData });
        const data = await res.json();
        if (!res.ok) { msg.textContent = data.error || 'Signup failed'; return; }
        localStorage.setItem('token', data.token);
        location.href = '/feed';
      } catch (err) {
        msg.textContent = 'Network error';
      }
    };

    // goto signup
    document.getElementById('gotoSignup').onclick = (e) => {
      e.preventDefault();
      window.scrollTo({ top: 200, behavior: 'smooth' });
    }
  </script>
</body>
</html>
  `;
}

function feedPageHTML() {
  return `
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Write-Commune — Feed</title>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <style>
    :root{--blue:#0073b1;--muted:#6b7280;--card:#fff;--bg:#f3f4f6}
    body{font-family:Inter,system-ui,Arial,Helvetica,sans-serif;background:var(--bg);margin:0}
    header{background:linear-gradient(0deg,#006696, #0073b1);color:white;padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
    .brand{font-weight:700;font-size:18px}
    .container{max-width:980px;margin:20px auto;padding:8px}
    .layout{display:grid;grid-template-columns:260px 1fr 320px;gap:18px}
    .card{background:var(--card);border-radius:8px;padding:16px;box-shadow:0 6px 18px rgba(0,0,0,0.06)}
    .profile{display:flex;gap:12px;align-items:center}
    .avatar{width:56px;height:56px;border-radius:8px;background:#ddd;overflow:hidden}
    .post-form textarea{width:100%;min-height:90px;border-radius:6px;border:1px solid #e5e7eb;padding:8px}
    button{background:var(--blue);color:white;padding:8px 12px;border-radius:6px;border:0;cursor:pointer}
    .post{padding:14px;border-bottom:1px solid #eef2f6}
    .muted{color:var(--muted);font-size:13px}
    .small{font-size:13px}
    .top-actions{display:flex;gap:8px;align-items:center}
    .logout{background:transparent;border:1px solid rgba(255,255,255,0.18);color:white;padding:6px 10px;border-radius:6px}
  </style>
</head>
<body>
  <header>
    <div style="display:flex;align-items:center;gap:12px">
      <div class="brand">Write-Commune</div>
      <div class="muted" style="margin-left:8px">Professional feed</div>
    </div>
    <div>
      <button class="logout" id="logoutBtn">Logout</button>
    </div>
  </header>

  <div class="container">
    <div class="layout">
      <div>
        <div class="card">
          <div class="profile">
            <div id="meAvatar" class="avatar"></div>
            <div>
              <div id="meName" style="font-weight:700"></div>
              <div id="meEmail" class="muted small"></div>
            </div>
          </div>
          <div style="height:12px"></div>
          <div class="muted small">Share something professionally relevant — your post will show your name & photo.</div>
        </div>
      </div>

      <div>
        <div class="card post-form">
          <textarea id="postContent" placeholder="What do you want to share?"></textarea>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px">
            <div class="muted small">No images in this demo — text only</div>
            <div>
              <button id="createPostBtn">Post</button>
            </div>
          </div>
        </div>

        <div style="height:12px"></div>

        <div id="feedCard" class="card">
          <div id="feedList">Loading feed…</div>
        </div>
      </div>

      <div>
        <div class="card">
          <h4>Tips</h4>
          <p class="muted small">Write helpful, thoughtful posts. This demo mimics a professional feed layout.</p>
        </div>
      </div>
    </div>
  </div>

  <script>
    const token = localStorage.getItem('token');
    if (!token) location.href = '/';

    document.getElementById('logoutBtn').onclick = () => {
      localStorage.removeItem('token');
      location.href = '/';
    };

    async function fetchMe() {
      // token contains user id embedded but we'll call /api/posts first to get posts and authors
      try {
        // display basic 'me' using token decode (not secure: quick decode)
        const payload = JSON.parse(atob(token.split('.')[1]));
        const myId = payload.id;
        const res = await fetch('/api/users/' + myId);
        if (!res.ok) throw new Error('no me');
        const me = await res.json();
        document.getElementById('meName').textContent = me.username;
        document.getElementById('meEmail').textContent = me.email;
        const avatarDiv = document.getElementById('meAvatar');
        const src = me.photo ? '/uploads/' + me.photo : '/avatar/default';
        avatarDiv.innerHTML = '<img src="'+src+'" style="width:100%;height:100%;object-fit:cover"/>';
      } catch (err) {
        console.warn('Could not load current user, redirecting to login', err);
        localStorage.removeItem('token');
        location.href = '/';
      }
    }

    async function loadFeed() {
      const el = document.getElementById('feedList');
      el.innerHTML = 'Loading…';
      try {
        const res = await fetch('/api/posts');
        const posts = await res.json();
        if (!Array.isArray(posts)) { el.textContent = 'Error loading feed'; return; }
        if (posts.length === 0) { el.innerHTML = '<div class="muted">No posts yet — be the first!</div>'; return; }
        const html = posts.map(p => {
          const author = p.author || {};
          const photo = author.photo ? '/uploads/' + author.photo : '/avatar/default';
          const name = author.username || 'Unknown';
          const time = new Date(p.createdAt).toLocaleString();
          return \`
            <div class="post">
              <div style="display:flex;gap:12px">
                <div style="width:56px;height:56px;border-radius:8px;overflow:hidden">
                  <img src="\${photo}" style="width:100%;height:100%;object-fit:cover"/>
                </div>
                <div style="flex:1">
                  <div style="display:flex;justify-content:space-between">
                    <div>
                      <div style="font-weight:700">\${name}</div>
                      <div class="muted small">\${time}</div>
                    </div>
                  </div>
                  <div style="margin-top:8px;white-space:pre-wrap">\${escapeHtml(p.content)}</div>
                </div>
              </div>
            </div>
          \`;
        }).join('');
        el.innerHTML = html;
      } catch (err) {
        el.textContent = 'Network error';
      }
    }

    function escapeHtml(text) {
      return (text || '').replace(/[&<>"'\/]/g, function (s) {
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',\"'\":'&#39;', '/':'&#x2F;'}[s];
      });
    }

    document.getElementById('createPostBtn').onclick = async () => {
      const content = document.getElementById('postContent').value.trim();
      if (!content) return alert('Write something first');
      try {
        const res = await fetch('/api/posts', {
          method: 'POST',
          headers: { 'Content-Type':'application/json', 'Authorization': 'Bearer ' + token },
          body: JSON.stringify({ content })
        });
        const data = await res.json();
        if (!res.ok) return alert(data.error || 'Error posting');
        document.getElementById('postContent').value = '';
        loadFeed();
      } catch (err) {
        alert('Network error');
      }
    };

    // initial load
    fetchMe();
    loadFeed();
    // refresh feed every 20s
    setInterval(loadFeed, 20000);
  </script>
</body>
</html>
  `;
}
