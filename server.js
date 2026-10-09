// ======= server.js =======
var express = require('express');
var mongoose = require('mongoose');
var path = require('path');
const { nanoid } = require('nanoid');
var session = require('express-session');
var bcrypt = require('bcrypt');
var User = require('./models/User');
var app = express();
var Url = require('./models/Url')

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config(); // Only load from .env in dev
}

const apik = process.env.GOOGLE_API_KEY;
let warnedSafeBrowsing = false;

// ---- Session secret ----
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  sessionSecret = 'dev-insecure-secret-change-me';
  console.warn('[WARN] SESSION_SECRET not set. Falling back to an insecure development default. Set SESSION_SECRET in production.');
}

// Needed for secure cookies to work correctly behind Render's proxy.
if (process.env.NODE_ENV === 'production') {
  app.set('trust proxy', 1);
}

app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 day
    sameSite: 'lax',             // helps prevent CSRF
    secure: process.env.NODE_ENV === 'production',
  }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public')); // point to where your templates are

// ---- Mongo connection ----
const mongoUri = process.env.MONGO_URI;
if (!mongoUri) {
  throw new Error('MONGO_URI environment variable is required.');
}

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const axios = require('axios');

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// ---- Middleware ----

// Prevents bfcache/back-button from showing stale session-aware pages.
function noCache(req, res, next) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function redirectIfAuthed(req, res, next) {
  if (req.session && req.session.user) {
    return res.redirect('/dashboard');
  }
  next();
}

// ---- Helpers ----

async function getDashboardRows(email, req) {
  const docs = await Url.find({ userEmail: email }).sort({ createdAt: -1 });
  const rows = [];
  for (const i of docs) {
    rows.push({
      shortId: i.shortId,
      s: `${req.protocol}://${req.get('host')}/${i.shortId}`,
      l: i.originalUrl,
      c: i.clicks,
      createdAt: i.createdAt,
    });
  }
  return rows;
}

async function isUrlSafe(url) {
  const apiKey = apik;
  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: {
      clientId: "url-checker-462415",
      clientVersion: "137.0.7151.69"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: url }]
    }
  }

  try {
    const response = await axios.post(apiUrl, body);
    return !response.data.matches; // true if no threats found
  } catch (error) {
    console.error('Error checking URL safety:', error);
    return false; // treat as unsafe on error
  }
}

// ---- Routes ----

app.get("/", noCache, async (req, res) => {
  if (req.session.user) {
    return res.render("home", { user: true, activePage: 'home' })
  }
  else {
    return res.render("home", { user: false, activePage: 'home' })
  }
})

// Signup route
app.post('/signup', redirectIfAuthed, async (req, res) => {
  var { email, password } = req.body;
  if (typeof email === 'string') {
    email = email.trim().toLowerCase();
  }
  if (typeof email !== 'string' || !email.trim() || typeof password !== 'string' || !password) {
    // Guards bcrypt.hash below, which throws synchronously on non-string input
    // (e.g. a raw POST with the password field omitted) and would otherwise
    // surface as an unhandled rejection instead of a clean error message.
    return res.status(400).render('signup', { user: false, activePage: 'signup', error: 'Please provide a valid email and password.' });
  }
  var hashed = await bcrypt.hash(password, 10);
  try {
    await User.create({ email, password: hashed });
    // Auto-login after signup.
    req.session.user = email;
    return res.redirect('/dashboard');
  } catch (e) {
    if (e && e.code === 11000) {
      return res.status(409).render('signup', { user: false, activePage: 'signup', error: 'Email may already be used.' });
    }
    console.error('Signup error:', e);
    return res.status(500).render('signup', { user: false, activePage: 'signup', error: 'Something went wrong. Please try again.' });
  }
});

// Login route
app.post('/login', redirectIfAuthed, async (req, res) => {
  var { email, password } = req.body;
  if (typeof email === 'string') {
    email = email.trim().toLowerCase();
  }
  if (typeof email !== 'string' || !email.trim() || typeof password !== 'string' || !password) {
    // Guards bcrypt.compare below, which throws synchronously on non-string
    // input instead of returning false.
    return res.status(401).render('login', { user: false, activePage: 'login', error: 'Incorrect email or password.' });
  }
  var user = await User.findOne({ email });
  if (!user) {
    return res.status(401).render('login', { user: false, activePage: 'login', error: 'Incorrect email or password.' });
  }

  var match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).render('login', { user: false, activePage: 'login', error: 'Incorrect email or password.' });
  }

  req.session.user = email;
  res.redirect('/dashboard');
});


app.get('/dashboard', noCache, requireAuth, async (req, res) => {
  var arr = await getDashboardRows(req.session.user, req);
  return res.render('dashboard', { arr: arr, activePage: 'dashboard', user: true });
})

app.post('/shorten', requireAuth, async (req, res) => {
  const { originalUrl } = req.body;
  const mail = req.session.user;

  let parsed;
  try {
    if (typeof originalUrl !== 'string' || !originalUrl.trim()) {
      throw new Error('empty');
    }
    parsed = new URL(originalUrl);
  } catch (e) {
    parsed = null;
  }
  if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:')) {
    const arr = await getDashboardRows(mail, req);
    return res.status(400).render('dashboard', {
      arr: arr,
      activePage: 'dashboard',
      user: true,
      error: 'Please enter a valid http:// or https:// URL.'
    });
  }

  if (!apik) {
    if (!warnedSafeBrowsing) {
      console.warn('[WARN] GOOGLE_API_KEY not set. Skipping Safe Browsing check (dev/local mode).');
      warnedSafeBrowsing = true;
    }
  } else {
    const safe = await isUrlSafe(originalUrl);
    if (!safe) {
      const arr = await getDashboardRows(mail, req);
      return res.status(400).render('dashboard', {
        arr: arr,
        activePage: 'dashboard',
        user: true,
        error: 'That URL was flagged as unsafe and was not shortened.'
      });
    }
  }

  try {
    await Url.create({ shortId: nanoid(7), originalUrl: originalUrl, userEmail: mail });
  } catch (e) {
    if (e && e.code === 11000) {
      // Extremely rare nanoid collision - retry once with a fresh id.
      await Url.create({ shortId: nanoid(7), originalUrl: originalUrl, userEmail: mail });
    } else {
      throw e;
    }
  }
  res.redirect('/dashboard')
});

app.post('/delete/:id', requireAuth, async (req, res) => {
  var id = req.params.id
  await Url.deleteOne({ shortId: id, userEmail: req.session.user })
  return res.redirect('/dashboard');
})

app.get('/login', noCache, redirectIfAuthed, (req, res) => {
  return res.render('login', { user: false, activePage: 'login' });
});

app.get('/signup', noCache, redirectIfAuthed, (req, res) => {
  return res.render('signup', { user: false, activePage: 'signup' });
});


// Logout
app.get('/logout', noCache, (req, res) => {
  req.session.destroy(() => {
    res.render('login', { user: false, activePage: 'login' });
  });
});

app.get('/:shortId', async (req, res) => {
  const shortId = req.params.shortId;
  try {
    const url = await Url.findOneAndUpdate({ shortId }, { $inc: { clicks: 1 } });
    if (url) {
      res.redirect(url.originalUrl);
    } else {
      res.status(404).render('error', { message: 'Short URL not found', user: !!req.session.user, activePage: '' });
    }
  } catch (err) {
    console.error('Redirect error:', err);
    res.status(500).render('error', { message: 'Server Error', user: !!req.session.user, activePage: '' });
  }
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;
