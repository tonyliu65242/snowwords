require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');
const db = require('./db');
const chatRoutes = require('./chat/chatRoutes');
const vocabRoutes = require('./chat/vocabRoutes');
const fileUpload = require('express-fileupload');
const nodemailer = require('nodemailer');
const pgSession = require('connect-pg-simple')(session);
const { ensurePremium, checkMessageLimit, checkTestLimit, checkGameAccess, injectFeatureAccess, FEATURE_LIMITS } = require('./middlewares/premiumAccess');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const stripeService = require('./services/stripeService');
const csurf = require('csurf');
const mainRoutes = require('./routes/mainRoutes');
const premiumRoutes = require('./routes/premiumRoutes');
const { generalLimiter, loginLimiter } = require('./middlewares/rateLimiter');

const app = express();

app.use(fileUpload());

// Ensure SESSION_SECRET is set
if (!process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET environment variable must be set for session security.');
}

// Configuration
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new pgSession({
    pool: db,
    tableName: 'user_sessions',
    createTableIfMissing: true,
    pruneSessionInterval: 60 * 15
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true
  },
  name: 'snowwords.sid'
}));

// Set trust proxy for correct session/cookie handling behind proxies like Cloudflare
app.set('trust proxy', 1);

// CORS support for Chrome extension - MUST be before CSRF protection
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Allow extension origins
  if (origin && origin.startsWith('chrome-extension://')) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-CSRF-Token');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  }
  
  next();
});

// Handle preflight requests for extension
app.options('/api/extension/*', (req, res) => {
  const origin = req.headers.origin;
  if (origin && origin.startsWith('chrome-extension://')) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, X-CSRF-Token');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  }
  res.sendStatus(200);
});

// Production-grade CSRF protection
const csrfProtection = csurf({
  cookie: false,
  sessionKey: 'session',
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  skip: function (req, res) {
    // Skip CSRF for routes that don't need it
    const skipPaths = [
      '/auth/',                    // OAuth callbacks (Google, future social logins)
      '/api/extension/',           // Extension API endpoints
      '/subscription/webhook',     // Payment webhooks (Stripe, PayPal)
      '/admin/api/'               // Admin API endpoints
    ];
    
    return skipPaths.some(path => req.path.startsWith(path));
  }
});

// Apply CSRF protection
app.use(csrfProtection);

// Enhanced CSRF token handling with error resilience
app.use((req, res, next) => {
  try {
    // Make sure session exists first
    if (req.session) {
      res.locals.csrfToken = req.csrfToken();
      console.log('CSRF token generated successfully:', res.locals.csrfToken.substring(0, 10) + '...');
    } else {
      console.error('No session found for CSRF token generation');
      res.locals.csrfToken = '';
    }
  } catch (err) {
    console.error('CSRF token generation failed:', err.message);
    res.locals.csrfToken = '';
  }
  next();
});

// CSRF token API endpoint with proper error handling
app.get('/api/csrf-token', (req, res) => {
  try {
    res.json({ 
      csrfToken: req.csrfToken(),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('CSRF token API error:', err);
    res.status(500).json({ error: 'Unable to generate CSRF token' });
  }
});

// Apply general rate limiting to all routes
app.use(generalLimiter);

// Passport Setup
app.use(passport.initialize());
app.use(passport.session());

app.use(injectFeatureAccess);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    const user = result.rows[0];
    done(null, user || false);
  } catch (error) {
    done(error);
  }
});

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    
    if (!user) return done(null, false, { message: 'User not found' });
    if (!user.password) return done(null, false, { message: 'Use Google login' });
    if (!bcrypt.compareSync(password, user.password))
      return done(null, false, { message: 'Incorrect password' });
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

// Determine callback URL based on environment
const googleCallbackURL = process.env.GOOGLE_CALLBACK_URL ||
                          (process.env.NODE_ENV === 'production'
                            ? 'https://snowwords.me/auth/google/callback'
                            : 'http://localhost:3000/auth/google/callback');

console.log('='.repeat(60));
console.log('GOOGLE OAUTH CONFIGURATION:');
console.log('Environment:', process.env.NODE_ENV || 'development');
console.log('Callback URL:', googleCallbackURL);
console.log('Client ID:', process.env.GOOGLE_CLIENT_ID ? 'SET' : 'NOT SET');
console.log('Client Secret:', process.env.GOOGLE_CLIENT_SECRET ? 'SET' : 'NOT SET');
console.log('='.repeat(60));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: googleCallbackURL
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const existingResult = await db.query('SELECT * FROM users WHERE googleId = $1', [profile.id]);
    const existingUser = existingResult.rows[0];
    
    if (existingUser) return done(null, existingUser);
    
    const newUserResult = await db.query(`
      INSERT INTO users (email, username, googleId) 
      VALUES ($1, $2, $3)
      RETURNING *
    `, [profile.emails[0].value, profile.displayName, profile.id]);
    
    const newUser = newUserResult.rows[0];
    return done(null, newUser);
  } catch (err) {
    return done(err);
  }
}));

// Middleware to ensure the user is authenticated
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  } else {
    // Store the URL the user was trying to access
    req.session.returnTo = req.originalUrl;
    console.log(`[AUTH] Storing return URL: ${req.originalUrl}`);
    res.redirect('/login');
  }
};

// Middleware to check if user has admin access
const ensureAdmin = (req, res, next) => {
  console.log('[ensureAdmin] Checking:', req.method, req.path, 'isAdmin:', req.session?.isAdmin);
  if (req.session.isAdmin) {
    return next();
  } else {
    // For API requests, return JSON instead of redirect
    if (req.path.startsWith('/admin/api')) {
      console.log('[ensureAdmin] Unauthorized API request, returning 401 JSON');
      return res.status(401).json({ error: 'Unauthorized. Please log in as admin.' });
    }
    console.log('[ensureAdmin] Unauthorized, redirecting to login');
    res.redirect('/admin/login');
  }
};

// -------------------------------------------------------------------
// CHROME EXTENSION API ENDPOINTS
// -------------------------------------------------------------------

// Authentication status for extension
app.get('/api/extension/auth-status', (req, res) => {
  try {
    if (req.isAuthenticated()) {
      res.json({
        authenticated: true,
        user: {
          id: req.user.id,
          username: req.user.username,
          email: req.user.email,
          subscriptionStatus: req.user.subscriptionstatus || 'free',
          englishLevel: req.user.englishlevel || 'Intermediate'
        }
      });
    } else {
      res.json({ authenticated: false });
    }
  } catch (error) {
    console.error('Extension auth check error:', error);
    res.status(500).json({ error: 'Authentication check failed' });
  }
});

// Get vocabulary count (for extension badge)
app.get('/api/extension/vocab-count', ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1', [req.user.id]);
    const count = parseInt(result.rows[0].count) || 0;
    res.json({ count });
  } catch (error) {
    console.error('Error getting vocabulary count:', error);
    res.status(500).json({ error: 'Failed to get vocabulary count' });
  }
});

// Get vocabulary statistics (for extension popup)
app.get('/api/extension/stats', ensureAuthenticated, async (req, res) => {
  try {
    // Total words
    const totalResult = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1', [req.user.id]);
    const totalWords = parseInt(totalResult.rows[0].count) || 0;

    // Mastered words (correctcount >= 5)
    const masteredResult = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1 AND correctcount >= 5', [req.user.id]);
    const masteredWords = parseInt(masteredResult.rows[0].count) || 0;
    
    // Current streak (use your existing function)
    const currentStreak = await getCurrentStreak(req.user.id);
    
    // Words added this week
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - weekStart.getDay());
    weekStart.setHours(0, 0, 0, 0);
    
    const thisWeekResult = await db.query(`
      SELECT COUNT(*) as count
      FROM vocabulary
      WHERE userid = $1 AND dateadded >= $2
    `, [req.user.id, weekStart.toISOString()]);
    const wordsThisWeek = parseInt(thisWeekResult.rows[0].count) || 0;
    
    res.json({
      totalWords,
      masteredWords,
      currentStreak,
      wordsThisWeek
    });
  } catch (error) {
    console.error('Error getting extension stats:', error);
    res.status(500).json({ error: 'Failed to get statistics' });
  }
});

// Define word for extension
app.post('/api/extension/define-word', ensureAuthenticated, async (req, res) => {
  try {
    const { word } = req.body;
    
    if (!word || word.trim().length === 0) {
      return res.status(400).json({ error: 'Word is required' });
    }
    
    const cleanWord = word.trim().toLowerCase();
    
    // Check if word already exists
    const existingResult = await db.query(
      'SELECT definition FROM vocabulary WHERE userid = $1 AND LOWER(word) = $2',
      [req.user.id, cleanWord]
    );
    
    if (existingResult.rows.length > 0) {
      return res.json({ 
        definition: existingResult.rows[0].definition,
        alreadyExists: true,
        message: 'This word is already in your vocabulary'
      });
    }
    
    // Get definition using your existing AI service
    const definition = await getWordDefinitionFromAI(cleanWord, req.user.englishlevel || 'Intermediate');
    
    res.json({ 
      definition: definition || 'No definition found for this word.',
      alreadyExists: false
    });
    
  } catch (error) {
    console.error('Error defining word for extension:', error);
    res.status(500).json({ error: 'Failed to get word definition' });
  }
});

// Add word to vocabulary from extension
app.post('/api/extension/add-word', ensureAuthenticated, async (req, res) => {
  try {
    const { word, definition, difficultyLevel } = req.body;
    
    if (!word || !definition) {
      return res.status(400).json({ error: 'Word and definition are required' });
    }
    
    const cleanWord = word.trim();
    const cleanDefinition = definition.trim();
    const difficulty = parseInt(difficultyLevel) || 2;
    
    // Check if word already exists
    const existingResult = await db.query(
      'SELECT id FROM vocabulary WHERE userid = $1 AND LOWER(word) = $2',
      [req.user.id, cleanWord.toLowerCase()]
    );
    
    if (existingResult.rows.length > 0) {
      return res.status(409).json({ 
        error: 'Word already exists in your vocabulary',
        alreadyExists: true
      });
    }
    
    // Add word to vocabulary
    const result = await db.query(`
      INSERT INTO vocabulary (word, definition, userid, difficultylevel, dateadded, correctcount)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, 0)
      RETURNING id
    `, [cleanWord, cleanDefinition, req.user.id, difficulty]);
    
    res.json({
      success: true,
      vocabId: result.rows[0].id,
      word: cleanWord,
      message: 'Word added successfully!'
    });
    
  } catch (error) {
    console.error('Error adding word from extension:', error);
    res.status(500).json({ error: 'Failed to add word to vocabulary' });
  }
});

// Extension-specific vocabulary list endpoint
app.get('/api/extension/recent-words', ensureAuthenticated, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    
    const result = await db.query(`
      SELECT word, definition, difficultylevel, correctcount, dateadded
      FROM vocabulary
      WHERE userid = $1
      ORDER BY dateadded DESC
      LIMIT $2
    `, [req.user.id, limit]);
    
    res.json({
      words: result.rows,
      total: result.rows.length
    });
  } catch (error) {
    console.error('Error getting recent vocabulary:', error);
    res.status(500).json({ error: 'Failed to get recent vocabulary' });
  }
});

// Word lookup endpoint for quick definitions
app.get('/api/extension/lookup/:word', ensureAuthenticated, async (req, res) => {
  try {
    const { word } = req.params;
    const cleanWord = word.trim().toLowerCase();
    
    // Check if word exists in user's vocabulary
    const result = await db.query(`
      SELECT word, definition, difficultylevel, correctcount, dateadded
      FROM vocabulary
      WHERE userid = $1 AND LOWER(word) = $2
    `, [req.user.id, cleanWord]);
    
    if (result.rows.length > 0) {
      res.json({
        found: true,
        word: result.rows[0]
      });
    } else {
      res.json({
        found: false,
        message: 'Word not found in your vocabulary'
      });
    }
  } catch (error) {
    console.error('Error looking up word:', error);
    res.status(500).json({ error: 'Failed to lookup word' });
  }
});

// Helper function to get word definition (integrate with your existing AI service)
async function getWordDefinitionFromAI(word, userLevel) {
  try {
    const { sendToGemini } = require('./chat/geminiClient');
    const CacheService = require('./services/cacheService');
    
    console.log(`Getting AI definition for: ${word} (level: ${userLevel})`);
    
    // Sanitize input (copied directly from your vocabRoutes)
    const cleanWord = (word || '').trim().replace(/[<>]/g, '').slice(0, 50);
    
    if (!cleanWord) {
      return 'Invalid word provided.';
    }

    // Use EXACT same prompt as your vocabRoutes aiLookup function
    const defPrompt = `
      You are a helpful AI. The user wants to learn a new English word: "${cleanWord}".
      Please respond EXACTLY with one line:
      "Definition: <short definition>"
    `;
    
    // Check cache for AI response (same as vocabRoutes)
    let defReply = CacheService.getAIResponse(defPrompt);
    if (!defReply) {
      console.log('Making AI call to Gemini for:', cleanWord);
      defReply = await sendToGemini(defPrompt);
      CacheService.setAIResponse(defPrompt, defReply);
    } else {
      console.log('Found cached AI response for:', cleanWord);
    }
    
    // Parse definition using same logic as vocabRoutes parseAiDefinition
    let definition = 'No definition found.';
    const match = defReply.match(/definition:\s*(.*)/i);
    if (match && match[1]) {
      definition = match[1].trim();
    } else {
      definition = defReply.trim();
    }
    
    console.log('AI definition result:', definition);
    return definition;
    
  } catch (error) {
    console.error('Error getting AI definition:', error);
    return `Definition for "${word}". Please try again.`;
  }
}

// -------------------------------------------------------------------
// Helper Functions for Stats & Achievements
// -------------------------------------------------------------------

// For generating decoy definitions in tests.
async function getDecoyDefinitions(correctDef, userId) {
  try {
    const result = await db.query(`
      SELECT definition FROM vocabulary
      WHERE userid = $1 AND definition != $2
    `, [userId, correctDef]);
    
    const allDefs = result.rows.map(v => v.definition);
    return shuffleArray(allDefs).slice(0, 3);
  } catch (error) {
    console.error('Error getting decoy definitions:', error);
    return [];
  }
}

// Simple in-place shuffle.
function shuffleArray(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// Helper functions for stats (you'll need to import these from your utils file)
async function getCurrentStreak(userId) {
  try {
    const result = await db.query(`
      SELECT DATE(timestamp) as date
      FROM messages
      WHERE userid = $1
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
      LIMIT 30
    `, [userId]);

    const rows = result.rows;
    if (!rows.length) return 0;

    const todayStr = new Date().toISOString().split('T')[0];
    if (rows[0].date !== todayStr) return 0;

    let streak = 1;
    let prevDate = new Date(rows[0].date);
    for (let i = 1; i < rows.length; i++) {
      let currentRowDate = new Date(rows[i].date);
      const diffDays = (prevDate - currentRowDate) / (1000 * 3600 * 24);
      if (diffDays === 1) {
        streak++;
        prevDate = currentRowDate;
      } else {
        break;
      }
    }
    return streak;
  } catch (error) {
    console.error('Error getting current streak:', error);
    return 0;
  }
}

async function getTotalStudyHours(userId) {
  try {
    const result = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1', [userId]);
    return parseFloat((result.rows[0].count * 0.2).toFixed(1));
  } catch (error) {
    console.error('Error getting total study hours:', error);
    return 0;
  }
}

async function calculateAccuracy(userId) {
  try {
    const result = await db.query('SELECT correctcount FROM vocabulary WHERE userid = $1', [userId]);
    const rows = result.rows;

    if (!rows.length) return 0;
    let total = 0;
    rows.forEach(row => {
      total += Math.min(row.correctcount, 5);
    });
    const accuracy = (total / (rows.length * 5)) * 100;
    return Math.floor(accuracy);
  } catch (error) {
    console.error('Error calculating accuracy:', error);
    return 0;
  }
}

// Replace this function
async function getAchievements(userId) {
  // --- 1) Collect metrics we need -----------------------------
  // (We keep the same column casing your file already uses elsewhere.)
  const [
    vocabCountRes,
    learnedRes,
    testsRes,
    messagesRes
  ] = await Promise.all([
    db.query('SELECT COUNT(*)::int AS c FROM vocabulary WHERE userid = $1', [userId]),
    db.query('SELECT COUNT(*)::int AS c FROM vocabulary WHERE userid = $1 AND correctcount >= 5', [userId]),
    db.query('SELECT COUNT(*)::int AS c FROM tests_taken WHERE userid = $1', [userId]),
    db.query('SELECT COUNT(*)::int AS c FROM messages WHERE userid = $1', [userId]),
  ]);

  const vocabCount   = vocabCountRes.rows[0].c || 0;
  const learnedCount = learnedRes.rows[0].c || 0;
  const testsTaken   = testsRes.rows[0].c || 0;
  const messageCount = messagesRes.rows[0].c || 0;

  // words added this week (use same week logic already used elsewhere in your file)
  const weekStart = new Date();
  weekStart.setDate(weekStart.getDate() - weekStart.getDay());
  weekStart.setHours(0, 0, 0, 0);
  const weekRes = await db.query(
    `SELECT COUNT(*)::int AS c FROM vocabulary WHERE userid = $1 AND dateadded >= $2`,
    [userId, weekStart.toISOString()]
  );
  const wordsThisWeek = weekRes.rows[0].c || 0;

  // Early bird / Night owl (distinct days)
  const earlyBirdRes = await db.query(
    `SELECT COUNT(DISTINCT DATE(timestamp))::int AS c
       FROM messages
      WHERE userId = $1 AND EXTRACT(HOUR FROM timestamp) BETWEEN 5 AND 8`,
    [userId]
  );
  const nightOwlRes = await db.query(
    `SELECT COUNT(DISTINCT DATE(timestamp))::int AS c
       FROM messages
      WHERE userId = $1
        AND (EXTRACT(HOUR FROM timestamp) >= 22 OR EXTRACT(HOUR FROM timestamp) < 3)`,
    [userId]
  );
  const earlyBirdDays = earlyBirdRes.rows[0].c || 0;
  const nightOwlDays  = nightOwlRes.rows[0].c || 0;

  // Reuse your helpers
  const streak     = await getCurrentStreak(userId);
  const totalHours = await getTotalStudyHours(userId);
  const accuracy   = await calculateAccuracy(userId);

  const M = {
    vocabCount, learnedCount, testsTaken, messageCount,
    wordsThisWeek, earlyBirdDays, nightOwlDays, streak, totalHours, accuracy
  };

  // --- 2) Define the catalog ---------------------------------
  const CATALOG = [
    { key:'first_word',   emoji:'🌱', name:'First Word',           desc:'Add your first word',            metric:'vocabCount',   target:1 },
    { key:'vocab_10',     emoji:'🧊', name:'10 Words',             desc:'Reach 10 words',                 metric:'vocabCount',   target:10 },
    { key:'vocab_50',     emoji:'❄️', name:'50 Words',             desc:'Reach 50 words',                 metric:'vocabCount',   target:50 },
    { key:'vocab_100',    emoji:'⛄️', name:'100 Words',            desc:'Reach 100 words',                metric:'vocabCount',   target:100 },

    { key:'master_20',    emoji:'🏆', name:'20 Mastered',          desc:'Master 20 words (5/5)',          metric:'learnedCount', target:20 },

    { key:'streak_3',     emoji:'🔥', name:'3-Day Streak',         desc:'Study 3 days in a row',          metric:'streak',       target:3 },
    { key:'streak_7',     emoji:'🔥', name:'7-Day Streak',         desc:'Study 7 days in a row',          metric:'streak',       target:7 },
    { key:'streak_14',    emoji:'🔥', name:'14-Day Streak',        desc:'Study 14 days in a row',         metric:'streak',       target:14 },

    { key:'accuracy_70',  emoji:'🎯', name:'Accuracy 70%',         desc:'Reach 70% answer accuracy',      metric:'accuracy',     target:70 },
    { key:'accuracy_85',  emoji:'🎯', name:'Accuracy 85%',         desc:'Reach 85% answer accuracy',      metric:'accuracy',     target:85 },
    { key:'accuracy_95',  emoji:'🎯', name:'Accuracy 95%',         desc:'Reach 95% answer accuracy',      metric:'accuracy',     target:95 },

    { key:'study_5h',     emoji:'⌛', name:'5 Study Hours',        desc:'Accumulate 5 hours of study',    metric:'totalHours',   target:5 },
    { key:'study_20h',    emoji:'⌛', name:'20 Study Hours',       desc:'Accumulate 20 hours of study',   metric:'totalHours',   target:20 },

    { key:'tests_5',      emoji:'📝', name:'Quiz Novice',          desc:'Complete 5 tests',               metric:'testsTaken',   target:5 },
    { key:'tests_10',     emoji:'📝', name:'Quiz Master',          desc:'Complete 10 tests',              metric:'testsTaken',   target:10 },

    { key:'week_10',      emoji:'📈', name:'+10 this week',        desc:'Add 10 words this week',         metric:'wordsThisWeek',target:10 },
    { key:'marathon_100', emoji:'💬', name:'Chat Marathon',        desc:'Send 100 messages',              metric:'messageCount', target:100 },

    { key:'early_bird',   emoji:'🌅', name:'Early Bird',           desc:'Study between 5–8am (any day)',  metric:'earlyBirdDays',target:1 },
    { key:'night_owl',    emoji:'🌙', name:'Night Owl',            desc:'Study between 10pm–3am (any day)', metric:'nightOwlDays',target:1 },
  ];

  // --- 3) Compute earned + progress ---------------------------
  return CATALOG.map(a => {
    const current = Number(M[a.metric] ?? 0);
    const target  = Number(a.target ?? 0);
    const earned  = current >= target;
    const progress = target > 0 ? Math.max(0, Math.min(1, current / target)) : (earned ? 1 : 0);

    return {
      key: a.key,
      emoji: a.emoji,
      name: a.name,
      description: a.desc,
      earned,
      current,
      target,
      progress
    };
  });
}

// -------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------

app.get('/', async (req, res) => {
  try {
    const user = req.user;
    if (user) {
      // Count learned words (correctCount >= 5)
      const learnedResult = await db.query(`
        SELECT COUNT(*) as count FROM vocabulary 
        WHERE userId = $1 AND correctCount >= 5
      `, [user.id]);
      const learnedCount = parseInt(learnedResult.rows[0].count);

      // Progress is calculated as a percentage toward a goal of 100 learned words.
      const progress = Math.min(Math.floor((learnedCount / 100) * 100), 100);

      res.render('index', { 
        user: {
          ...user,
          progress,
          learnedCount
        }
      });
    } else {
      res.render('index', { user: null });
    }
  } catch (err) {
    console.error('Error loading home page:', err);
    res.render('index', { user: null, error: 'Error loading progress' });
  }
});

// Auth Routes
app.get('/login', (req, res) => {
  // Only set returnTo if not already set (e.g., from ensureAuthenticated)
  if (!req.session.returnTo && req.headers.referer) {
    try {
      const refererUrl = new URL(req.headers.referer);
      const requestHost = req.get('host');
      // Only set returnTo if the referer is from our site and not /login or /signup
      if (
        refererUrl.host === requestHost &&
        !refererUrl.pathname.includes('/login') &&
        !refererUrl.pathname.includes('/signup')
      ) {
        req.session.returnTo = refererUrl.pathname;
        console.log(`[LOGIN PAGE] Setting returnTo from referer: ${req.session.returnTo}`);
      }
    } catch (err) {
      console.log('[LOGIN PAGE] Error parsing referer URL:', err);
    }
  }
  res.render('login', { error: null });
});

app.post('/login', loginLimiter, (req, res, next) => {
  console.log('Session ID at login:', req.sessionID);
  console.log('Session returnTo at login:', req.session.returnTo);
  let returnTo = req.session.returnTo;
  console.log('Raw returnTo:', JSON.stringify(returnTo));
  if (!returnTo || returnTo.trim() === '/') {
    returnTo = '/activities';
  } else {
    returnTo = returnTo.trim();
  }
  delete req.session.returnTo;
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) { 
      return res.render('login', { error: info?.message || 'Authentication failed' }); 
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      console.log('Redirecting to:', returnTo);
      return res.redirect(returnTo);
    });
  })(req, res, next);
});

app.get('/signup', (req, res) => res.render('signup', { error: null }));

app.post('/signup', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    
    const existingResult = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingResult.rows[0]) {
      return res.render('signup', { error: 'Email already exists' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    await db.query(`
      INSERT INTO users (email, password, username)
      VALUES ($1, $2, $3)
    `, [email, hashedPassword, username]);
    
    res.redirect('/login');
  } catch (err) {
    console.error('Signup error:', err);
    res.render('signup', { error: 'Registration failed' });
  }
});

app.get('/auth/google', (req, res, next) => {
  // Store the returnTo in a query parameter to preserve it through the OAuth flow
  let returnPath = '/activities';
  
  // Try to get returnTo from session first
  if (req.session.returnTo && req.session.returnTo !== '/') {
    returnPath = req.session.returnTo;
    console.log(`[GOOGLE AUTH] Using returnTo from session: ${returnPath}`);
  } 
  // If not in session, try to get from referer
  else if (req.headers.referer) {
    try {
      const refererUrl = new URL(req.headers.referer);
      const currentHost = req.get('host');
      
      if (refererUrl.host === currentHost && !refererUrl.pathname.includes('/login')) {
        returnPath = refererUrl.pathname;
        console.log(`[GOOGLE AUTH] Setting returnTo from referer: ${returnPath}`);
      }
    } catch (err) {
      console.log('[GOOGLE AUTH] Error parsing referer URL:', err);
    }
  }
  
  // Use the OAuth state parameter to preserve the return URL
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    state: returnPath, // Pass returnPath as state parameter
    prompt: 'select_account' // Force account selection every time
  })(req, res, next);
});

app.get('/auth/google/callback', (req, res, next) => {
  // The state parameter comes back from Google in the request
  const returnTo = req.query.state && req.query.state !== '/' ? req.query.state : '/activities';
  console.log(`[GOOGLE CALLBACK] State parameter retrieved: ${returnTo}`);
  
  passport.authenticate('google', (err, user, info) => {
    if (err) { return next(err); }
    
    if (!user) { 
      return res.redirect('/login'); 
    }
    
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      
      console.log(`[GOOGLE] After auth, redirecting to: ${returnTo}`);
      return res.redirect(returnTo);
    });
  })(req, res, next);
});

app.get('/logout', (req, res, next) => {
  req.logout(function (err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

// -------------------------------------------------------------------
// Profile Route (with full stats & achievements functionality)
// -------------------------------------------------------------------
app.get('/profile', ensureAuthenticated, async (req, res) => {
  try {
    const user = req.user;
    
    // Get all vocabulary (for preview) and count total words
    const vocabResult = await db.query(`
      SELECT word FROM vocabulary
      WHERE userid = $1
      ORDER BY dateadded DESC
      LIMIT 15
    `, [user.id]);
    const vocab = vocabResult.rows;

    const vocabCountResult = await db.query(`
      SELECT COUNT(*) as count FROM vocabulary
      WHERE userid = $1
    `, [user.id]);
    const vocabCount = parseInt(vocabCountResult.rows[0].count);

    // Count learned words (correctcount >= 5)
    const learnedResult = await db.query(`
      SELECT COUNT(*) as count FROM vocabulary
      WHERE userid = $1 AND correctcount >= 5
    `, [user.id]);
    const learnedCount = parseInt(learnedResult.rows[0].count);

    // Progress is calculated as a percentage toward a goal of 100 learned words.
    const progress = Math.min(Math.floor((learnedCount / 100) * 100), 100);

    // Calculate additional stats using our helper functions.
    const streak = await getCurrentStreak(user.id);
    const totalHours = await getTotalStudyHours(user.id);
    const accuracy = await calculateAccuracy(user.id);

    // Full achievements with progress/unlocks
    const achievements = await getAchievements(user.id);

    // Get user's active subscription if any
    const subscriptionResult = await db.query(`
      SELECT s.*, p.name as planName, p.price, p.billing_interval
      FROM subscriptions s
      JOIN subscription_plans p ON s.planid = p.id
      WHERE s.userid = $1 AND s.status = 'active'
      ORDER BY s.id DESC LIMIT 1
    `, [user.id]);
    const subscription = subscriptionResult.rows[0] || null;

    res.render('profile', {
      user: {
        ...user,
        subscriptionstatus: subscription ? 'premium' : 'free',
        progress,
        vocabulary: vocab,
        vocabCount,
        streak,
        totalHours,
        accuracy,
        achievements
      },
      subscription: subscription,
      error: null
    });
  } catch (err) {
    console.error('Error loading profile:', err);
    res.render('profile', { error: 'Error loading profile' });
  }
});

app.post('/update-profile', ensureAuthenticated, async (req, res) => {
  try {
    const { username, englishLevel, learningGoals } = req.body;
    
    await db.query(`
      UPDATE users SET 
      username = $1, 
      englishLevel = $2, 
      learningGoals = $3 
      WHERE id = $4
    `, [username, englishLevel, learningGoals, req.user.id]);

    const updatedResult = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const updatedUser = updatedResult.rows[0];
    
    req.login(updatedUser, (err) => {
      if (err) throw err;
      res.redirect('/profile');
    });
  } catch (err) {
    console.error('Error updating profile:', err);
    res.render('profile', { error: 'Update failed' });
  }
});

app.post('/delete-account', ensureAuthenticated, async (req, res) => {
  try {
    // Delete in proper order to handle foreign key constraints
    await db.query('DELETE FROM messages WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM vocabulary WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM feedback WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM payment_history WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM subscriptions WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM tests_taken WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM pronunciation_practice WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM study_reminders WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM study_goals WHERE userId = $1', [req.user.id]);
    await db.query('DELETE FROM users WHERE id = $1', [req.user.id]);
    
    req.logout((err) => {
      if (err) {
        console.error('Logout error:', err);
        return res.render('profile', { error: 'Delete failed' });
      }
      res.redirect('/');
    });
  } catch (err) {
    console.error('Error deleting account:', err);
    res.render('profile', { error: 'Delete failed' });
  }
});

// Test endpoint to list available Gemini models
app.get('/api/test-models', async (req, res) => {
  try {
    const axios = require('axios');
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        error: 'GEMINI_API_KEY not configured'
      });
    }

    // Make direct API call to list models
    const response = await axios.get(
      `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`
    );

    const models = response.data.models || [];
    const modelList = models
      .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
      .map(m => ({
        name: m.name,
        displayName: m.displayName,
        description: m.description,
        supportedMethods: m.supportedGenerationMethods
      }));

    res.json({
      success: true,
      count: modelList.length,
      models: modelList,
      note: 'These are the models available for generateContent with your API key'
    });
  } catch (error) {
    console.error('Error listing models:', error);
    res.status(500).json({
      error: 'Failed to list models',
      message: error.message,
      details: error.response?.data
    });
  }
});

// Chat Routes
app.use('/api/chat', ensureAuthenticated, chatRoutes);

app.get('/chat', ensureAuthenticated, async (req, res) => {
  try {
    const messagesResult = await db.query(`
      SELECT * FROM messages 
      WHERE userId = $1
      ORDER BY id ASC
    `, [req.user.id]);
    const messages = messagesResult.rows;
    
    const vocabResult = await db.query(`
      SELECT word, definition
      FROM vocabulary
      WHERE userId = $1
      ORDER BY id DESC
    `, [req.user.id]);
    const vocab = vocabResult.rows;
    
    const levelResult = await db.query(`
      SELECT englishLevel 
      FROM users 
      WHERE id = $1
    `, [req.user.id]);
    const englishLevel = levelResult.rows[0];
    
    res.render('chat', {
      user: req.user,
      messages,
      vocab,
      englishLevel,
      snowballSize: vocab.length
    });
  } catch (err) {
    console.error('Error loading chat:', err);
    res.render('chat', { 
      user: req.user, 
      messages: [], 
      vocab: [], 
      englishLevel: { englishlevel: 'Intermediate' }, 
      snowballSize: 0 
    });
  }
});

app.post('/chat/clear', ensureAuthenticated, async (req, res) => {
  try {
    await db.query('DELETE FROM messages WHERE userId = $1', [req.user.id]);
    res.redirect('/chat');
  } catch (err) {
    console.error('Error clearing chat:', err);
    res.redirect('/chat');
  }
});

// Vocabulary Routes
app.use('/api/vocab', ensureAuthenticated, vocabRoutes);

// Get vocabulary count for crossword puzzle
app.get('/api/vocab/count', ensureAuthenticated, async (req, res) => {
  try {
    const countResult = await db.query(`
      SELECT COUNT(*) as count 
      FROM vocabulary 
      WHERE userId = $1
    `, [req.user.id]);
    
    res.json({ count: parseInt(countResult.rows[0].count) });
  } catch (err) {
    console.error('Error getting vocabulary count:', err);
    res.status(500).json({ error: 'Failed to get vocabulary count' });
  }
});

app.get('/vocab', ensureAuthenticated, async (req, res) => {
  try {
    const vocabResult = await db.query(`
      SELECT word, definition, correctCount 
      FROM vocabulary 
      WHERE userId = $1
      ORDER BY word ASC
    `, [req.user.id]);
    const vocabList = vocabResult.rows;
    
    res.render('vocab', { user: req.user, vocabList });
  } catch (err) {
    console.error('Error loading vocabulary:', err);
    res.render('vocab', { user: req.user, vocabList: [] });
  }
});

// Test Routes
app.get('/test', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

app.get('/test/data', checkTestLimit, async (req, res) => {
  try {
    // Record that user is taking a test
    await db.query(`
      INSERT INTO tests_taken (userId)
      VALUES ($1)
    `, [req.user.id]);
    
    // Get test data
    const vocabResult = await db.query(`
      SELECT id, word, definition 
      FROM vocabulary 
      WHERE userId = $1
    `, [req.user.id]);
    const vocabRows = vocabResult.rows;
    
    const questions = [];
    for (const v of vocabRows) {
      const decoyDefinitions = await getDecoyDefinitions(v.definition, req.user.id);
      questions.push({
        vocabId: v.id,
        questionWord: v.word,
        correctDefinition: v.definition,
        decoyDefinitions: decoyDefinitions
      });
    }
    
    res.json({ questions: shuffleArray(questions) });
  } catch (err) {
    console.error('Error getting test data:', err);
    res.json({ questions: [] });
  }
});

app.post('/test/correct', ensureAuthenticated, express.json(), async (req, res) => {
  try {
    const { vocabId } = req.body;
    
    const rowResult = await db.query(`
      SELECT correctCount, difficultyLevel 
      FROM vocabulary 
      WHERE id = $1 AND userId = $2
    `, [vocabId, req.user.id]);
    const row = rowResult.rows[0];
    
    if (!row) {
      return res.json({ error: 'Vocabulary not found' });
    }
    
    const newCount = (row.correctcount || 0) + 1;
    let newDifficulty = row.difficultylevel;
    if (newCount >= 5 && newDifficulty < 2) newDifficulty = 2;
    
    await db.query(`
      UPDATE vocabulary 
      SET correctCount = $1, difficultyLevel = $2
      WHERE id = $3
    `, [newCount, newDifficulty, vocabId]);
    
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating test result:', err);
    res.json({ error: 'Update failed' });
  }
});

// Review Routes
app.get('/review', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'review.html'));
});

app.get('/review/data', ensureAuthenticated, async (req, res) => {
  try {
    const vocabResult = await db.query(`
      SELECT word, definition
      FROM vocabulary
      WHERE userId = $1
      ORDER BY id ASC
    `, [req.user.id]);
    const vocab = vocabResult.rows;
    
    res.json(vocab);
  } catch (error) {
    console.error('Error fetching vocabulary:', error);
    res.json([]);
  }
});

app.post('/update-avatar', ensureAuthenticated, async (req, res) => {
  try {
    if (!req.files || !req.files.avatar) {
      return res.status(400).send('No file uploaded');
    }
    
    const avatar = req.files.avatar;
    const uploadDir = path.join(__dirname, 'public', 'uploads');
    const filename = `avatar-${req.user.id}${path.extname(avatar.name)}`;
    const filepath = path.join(uploadDir, filename);
    
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    await avatar.mv(filepath);
    const avatarUrl = `/uploads/${filename}`;
    
    await db.query('UPDATE users SET avatarUrl = $1 WHERE id = $2', [avatarUrl, req.user.id]);
    
    res.redirect('/profile');
  } catch (err) {
    console.error('Avatar upload error:', err);
    res.status(500).send('Error uploading avatar');
  }
});

// Feedback Routes
app.get('/feedback', (req, res) => {
  res.render('feedback', { 
    user: req.user, 
    success: req.query.success === 'true', 
    error: null 
  });
});

app.post('/feedback', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    
    // Validation
    if (!name || !email || !subject || !message) {
      return res.render('feedback', { 
        user: req.user, 
        success: false, 
        error: 'All fields are required' 
      });
    }
    
    // Store in database
    await db.query(`
      INSERT INTO feedback (name, email, subject, message, userId)
      VALUES ($1, $2, $3, $4, $5)
    `, [name, email, subject, message, req.user ? req.user.id : null]);
    
    // Redirect with success message
    res.redirect('/feedback?success=true');
  } catch (err) {
    console.error('Error processing feedback:', err);
    res.render('feedback', { 
      user: req.user, 
      success: false, 
      error: 'Failed to submit feedback. Please try again later.' 
    });
  }
});

// -------------------------------------------------------------------
// Admin Routes
// -------------------------------------------------------------------

// Admin Login Page
app.get('/admin/login', (req, res) => {
  res.render('admin-login', { error: null });
});

// Admin Login Logic - Using a simple password for access
app.post('/admin/login', (req, res) => {
  try {
    const { password } = req.body;
    // Use a hardcoded password (ideally this would be an environment variable)
    const adminPassword = process.env.ADMIN_PASSWORD || 'snowwords-admin';
    
    if (password === adminPassword) {
      // Set admin session flag
      req.session.isAdmin = true;
      res.redirect('/admin');
    } else {
      res.render('admin-login', { error: 'Invalid password' });
    }
  } catch (err) {
    console.error('Admin login error:', err);
    res.render('admin-login', { error: 'Login failed' });
  }
});

// Admin Logout
app.get('/admin/logout', (req, res) => {
  req.session.isAdmin = false;
  res.redirect('/admin/login');
});

// Admin dashboard page
app.get('/admin', ensureAdmin, (req, res) => {
  res.render('admin', { csrfToken: req.csrfToken() });
});

// Admin API: Get system stats
app.get('/admin/api/stats', ensureAdmin, async (req, res) => {
  try {
    console.log('Fetching admin stats...');
    
    // Get basic counts - these should work reliably
    const userResult = await db.query('SELECT COUNT(*) as count FROM users');
    const userCount = parseInt(userResult.rows[0].count) || 0;
    
    const vocabResult = await db.query('SELECT COUNT(*) as count FROM vocabulary');
    const vocabCount = parseInt(vocabResult.rows[0].count) || 0;
    
    const messageResult = await db.query('SELECT COUNT(*) as count FROM messages');
    const messageCount = parseInt(messageResult.rows[0].count) || 0;
    
    const feedbackResult = await db.query('SELECT COUNT(*) as count FROM feedback');
    const feedbackCount = parseInt(feedbackResult.rows[0].count) || 0;
    
    console.log(`Basic counts - Users: ${userCount}, Vocab: ${vocabCount}, Messages: ${messageCount}`);
    
    // Default response with just the basic stats
    let response = {
      totalUsers: userCount,
      totalVocab: vocabCount,
      totalMessages: messageCount,
      totalFeedback: feedbackCount,
      avgProgress: 0,
      messagesByDay: [0, 0, 0, 0, 0, 0, 0], // Sun-Sat
      vocabByDay: [0, 0, 0, 0, 0, 0, 0],  // Sun-Sat
      vocabMastery: [0, 0, 0, 0],  // Default empty mastery levels
      engagementByLevel: [0, 0, 0]  // Default empty engagement levels
    };
    
    try {
      // Get average progress - safely calculate this
      const usersResult = await db.query('SELECT id FROM users');
      const users = usersResult.rows || [];
      console.log(`Found ${users.length} users for progress calculation`);
      
      let totalProgress = 0;
      
      for (const user of users) {
        try {
          // Safely get counts with default values if query fails
          const learnedResult = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userId = $1 AND correctCount >= 5', [user.id]);
          const learnedCount = parseInt(learnedResult.rows[0].count) || 0;
          
          const totalWordsResult = await db.query('SELECT COUNT(*) as count FROM vocabulary WHERE userId = $1', [user.id]);
          const totalWords = parseInt(totalWordsResult.rows[0].count) || 0;
          
          // Calculate progress
          let progress = 0;
          if (totalWords > 0) {
            progress = Math.min(Math.floor((learnedCount / 100) * 100), 100);
          }
          
          totalProgress += progress;
        } catch (userErr) {
          console.error(`Error calculating progress for user ${user.id}:`, userErr);
          // Continue with next user if one fails
        }
      }
      
      response.avgProgress = users.length > 0 ? Math.round(totalProgress / users.length) : 0;
      console.log(`Average progress calculated: ${response.avgProgress}%`);
    } catch (progressErr) {
      console.error('Error calculating average progress:', progressErr);
      // Continue with default avgProgress
    }
    
    try {
      // Safely handle message distribution by day of week
      try {
        const recentMessagesResult = await db.query('SELECT timestamp FROM messages');
        const recentMessages = recentMessagesResult.rows || [];
        console.log(`Found ${recentMessages.length} messages for activity chart`);
        
        const messagesByDay = [0, 0, 0, 0, 0, 0, 0]; // Sun-Sat
        
        recentMessages.forEach(msg => {
          try {
            if (msg.timestamp) {
              const date = new Date(msg.timestamp);
              if (!isNaN(date.getTime())) { // Check if valid date
                const day = date.getDay(); // 0 = Sunday, 6 = Saturday
                if (day >= 0 && day <= 6) {
                  messagesByDay[day]++;
                }
              }
            }
          } catch (dateErr) {
            // Skip this message if date parsing fails
          }
        });
        
        response.messagesByDay = messagesByDay;
        console.log('Messages by day calculated:', messagesByDay);
      } catch (msgErr) {
        console.error('Error calculating messages by day:', msgErr);
        // Continue with default messagesByDay
      }
      
      // Safely handle vocabulary distribution by day of week
      try {
        const recentVocabResult = await db.query('SELECT dateAdded FROM vocabulary');
        const recentVocab = recentVocabResult.rows || [];
        console.log(`Found ${recentVocab.length} vocabulary entries for activity chart`);
        
        const vocabByDay = [0, 0, 0, 0, 0, 0, 0]; // Sun-Sat
        
        recentVocab.forEach(vocab => {
          try {
            if (vocab.dateadded) {
              const date = new Date(vocab.dateadded);
              if (!isNaN(date.getTime())) { // Check if valid date
                const day = date.getDay();
                if (day >= 0 && day <= 6) {
                  vocabByDay[day]++;
                }
              }
            }
          } catch (dateErr) {
            // Skip this vocab if date parsing fails
          }
        });
        
        response.vocabByDay = vocabByDay;
        console.log('Vocabulary by day calculated:', vocabByDay);
      } catch (vocabErr) {
        console.error('Error calculating vocabulary by day:', vocabErr);
        // Continue with default vocabByDay
      }
    } catch (activityErr) {
      console.error('Error calculating activity distribution:', activityErr);
      // Continue with default activity distributions
    }
    
    try {
      // Safely get vocabulary mastery distribution
      const masteredResult = await db.query("SELECT COUNT(*) as count FROM vocabulary WHERE correctCount >= 5");
      const learningResult = await db.query("SELECT COUNT(*) as count FROM vocabulary WHERE correctCount BETWEEN 3 AND 4");
      const practicingResult = await db.query("SELECT COUNT(*) as count FROM vocabulary WHERE correctCount BETWEEN 1 AND 2");
      const newResult = await db.query("SELECT COUNT(*) as count FROM vocabulary WHERE correctCount = 0 OR correctCount IS NULL");
      
      const masteryLevels = [
        parseInt(masteredResult.rows[0].count) || 0,
        parseInt(learningResult.rows[0].count) || 0,
        parseInt(practicingResult.rows[0].count) || 0,
        parseInt(newResult.rows[0].count) || 0
      ];
      
      response.vocabMastery = masteryLevels;
      console.log('Vocabulary mastery levels calculated:', masteryLevels);
    } catch (masteryErr) {
      console.error('Error calculating mastery levels:', masteryErr);
      // Continue with default masteryLevels
    }
    
    try {
      // Safely calculate engagement by English level
      const engagementByLevel = [0, 0, 0]; // Beginner, Intermediate, Advanced
      
      // Default to average per level if detailed calculation fails
      if (userCount > 0) {
        const avgEngagement = Math.min(50, Math.round((vocabCount + messageCount) / userCount));
        engagementByLevel[0] = Math.max(0, avgEngagement - 10); // Slightly lower for beginners
        engagementByLevel[1] = avgEngagement;
        engagementByLevel[2] = avgEngagement + 10; // Slightly higher for advanced
      }
      
      response.engagementByLevel = engagementByLevel;
      console.log('Engagement by level calculated:', engagementByLevel);
    } catch (engagementErr) {
      console.error('Error calculating engagement by level:', engagementErr);
      // Continue with default engagementByLevel
    }
    
    // Send the response
    console.log('Successfully compiled stats data');
    res.json(response);
  } catch (err) {
    console.error('Error fetching stats:', err);
    // Send a meaningful error response
    res.status(500).json({ 
      error: 'Failed to fetch stats',
      message: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Admin API: Get all users
app.get('/admin/api/users', ensureAdmin, async (req, res) => {
  try {
    console.log('[Admin API] Fetching users, query params:', req.query);
    const searchQuery = req.query.search;
    const simple = req.query.simple === 'true';

    // Get all users - basic query
    let query = `SELECT id, email, username FROM users`;
    const params = [];

    if (searchQuery) {
      query += ` WHERE (username ILIKE $1 OR email ILIKE $1)`;
      params.push(`%${searchQuery}%`);
    }

    query += ` ORDER BY id DESC`;

    if (searchQuery) {
      query += ` LIMIT 20`;
    }

    console.log('[Admin API] Executing query:', query);
    const usersResult = await db.query(query, params);
    const users = usersResult.rows;
    console.log('[Admin API] Found users:', users.length);

    // If searching or simple mode, add subscription status and return
    if (searchQuery || simple) {
      console.log('[Admin API] Simple mode, adding subscription status');
      // Add subscription status for each user - with error handling
      for (const user of users) {
        try {
          // Check subscription status
          const subResult = await db.query(`
            SELECT COUNT(*) as count FROM subscriptions
            WHERE userid = $1 AND status = 'active'
          `, [user.id]);
          user.subscriptionstatus = subResult.rows[0].count > 0 ? 'premium' : 'free';
        } catch (subError) {
          console.error('[Admin API] Error checking subscription for user', user.id, subError.message);
          user.subscriptionstatus = 'free'; // Default to free if error
        }
      }
      console.log('[Admin API] Returning users with status');
      return res.json(users);
    }

    // For each user, get additional stats (only when not searching and not simple mode)
    for (const user of users) {
      // Check subscription status
      try {
        const subResult = await db.query(`
          SELECT COUNT(*) as count FROM subscriptions
          WHERE userid = $1 AND status = 'active'
        `, [user.id]);
        user.subscriptionstatus = subResult.rows[0].count > 0 ? 'premium' : 'free';
      } catch (subError) {
        console.error('[Admin API] Error checking subscription for user', user.id, subError.message);
        user.subscriptionstatus = 'free'; // Default to free if error
      }

      // Get vocabulary count
      const vocabCountResult = await db.query(`
        SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1
      `, [user.id]);
      user.vocabCount = parseInt(vocabCountResult.rows[0].count);

      // Get learned count (mastered words)
      const learnedCountResult = await db.query(`
        SELECT COUNT(*) as count FROM vocabulary WHERE userid = $1 AND correctcount >= 5
      `, [user.id]);
      const learnedCount = parseInt(learnedCountResult.rows[0].count);

      // Calculate progress
      user.progress = user.vocabCount > 0 ? Math.min(Math.floor((learnedCount / 100) * 100), 100) : 0;

      // Get message count
      const messageCountResult = await db.query(`
        SELECT COUNT(*) as count FROM messages WHERE userid = $1
      `, [user.id]);
      user.messageCount = parseInt(messageCountResult.rows[0].count);
    }

    res.json(users);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Admin API: Test endpoint to verify database connectivity
app.get('/admin/api/test-users', ensureAdmin, async (req, res) => {
  try {
    console.log('[Test] Testing database connection...');
    const result = await db.query('SELECT COUNT(*) as count FROM users');
    const count = result.rows[0].count;
    console.log('[Test] User count:', count);

    const sample = await db.query('SELECT id, email, username FROM users LIMIT 3');
    console.log('[Test] Sample users:', sample.rows);

    res.json({
      success: true,
      userCount: count,
      sampleUsers: sample.rows
    });
  } catch (err) {
    console.error('[Test] Error:', err);
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// Admin API: Get user details
app.get('/admin/api/users/:id', ensureAdmin, async (req, res) => {
  try {
    const userId = Number(req.params.id);

    // 1) Load user (alias to camelCase for the frontend)
    const userResult = await db.query(`
      SELECT
        id,
        email,
        username,
        googleid          AS "googleId",
        englishlevel      AS "englishLevel",
        learninggoals     AS "learningGoals",
        avatarurl         AS "avatarUrl",
        subscriptionstatus AS "subscriptionStatus"
      FROM users
      WHERE id = $1
    `, [userId]);

    const user = userResult.rows[0];

    // If the user doesn't exist, return a stub so the panel still opens
    if (!user) {
      return res.json({
        notFound: true,
        user: {
          id: userId,
          email: '',
          username: '(deleted user)',
          googleId: null,
          englishLevel: null,
          learningGoals: null,
          avatarUrl: null,
          subscriptionstatus: 'free'
        },
        vocab: [],
        messages: [],
        stats: {
          vocabCount: 0,
          learnedCount: 0,
          messageCount: 0,
          streak: 0,
          totalHours: 0,
          accuracy: 0,
          progress: 0,
          firstActivity: 'No activity'
        },
        achievements: []
      });
    }

    // 2) Vocabulary: use real column names (lowercase) and alias to camelCase
    const vocabResult = await db.query(`
      SELECT
        id,
        word,
        definition,
        difficultylevel AS "difficultyLevel",
        correctcount    AS "correctCount",
        dateadded       AS "dateAdded"
      FROM vocabulary
      WHERE userid = $1
      ORDER BY word ASC
    `, [userId]);
    const vocab = vocabResult.rows;

    // 3) Messages (latest 100)
    const messagesRes = await db.query(`
      SELECT id, role, content, timestamp
      FROM messages
      WHERE userid = $1
      ORDER BY timestamp DESC
      LIMIT 100
    `, [userId]);
    const messages = messagesRes.rows;

    // 4) Stats
    const vocabCount   = vocab.length;
    const learnedCount = vocab.filter(v => (v.correctCount ?? 0) >= 5).length;
    const streak       = await getCurrentStreak(userId);
    const totalHours   = await getTotalStudyHours(userId);
    const accuracy     = await calculateAccuracy(userId);
    const progress     = vocabCount > 0 ? Math.min(Math.floor((learnedCount / 100) * 100), 100) : 0;

    // 5) First activity (safe, no typos or quoted columns)
    let firstActivity = 'No activity';
    let earliestTs = null;

    if (messages.length) {
      earliestTs = messages[messages.length - 1].timestamp;
    }
    if (vocab.length) {
      const oldestVocab = await db.query(
        `SELECT MIN(dateadded) AS firstdate
         FROM vocabulary
         WHERE userid = $1`,
        [userId]
      );
      const fd = oldestVocab.rows?.[0]?.firstdate;
      if (fd && (!earliestTs || new Date(fd) < new Date(earliestTs))) {
        earliestTs = fd;
      }
    }
    if (earliestTs) {
      firstActivity = new Date(earliestTs).toLocaleDateString();
    }

    // 6) Achievements (keep your helper; if it's not defined it will throw—add a fallback if needed)
    const achievements = typeof getAchievements === 'function'
      ? await getAchievements(userId)
      : [];

    // 7) Respond in the exact shape the UI expects
    res.json({
      user,
      vocab,
      messages,
      stats: {
        vocabCount,
        learnedCount,
        messageCount: messages.length,
        streak,
        totalHours,
        accuracy,
        progress,
        firstActivity
      },
      achievements
    });
  } catch (err) {
    console.error('Error fetching user details:', err);
    res.status(500).json({ error: 'Failed to fetch user details' });
  }
});



// Admin API: Recent activity (messages + vocabulary), newest first
app.get('/admin/api/activity', ensureAdmin, async (req, res) => {
  try {
    const msgRes = await db.query(`
      SELECT m.timestamp AS ts, u.username, m.role
      FROM messages m
      LEFT JOIN users u ON u.id = m.userId
      ORDER BY m.timestamp DESC
      LIMIT 50
    `);

    const vocabRes = await db.query(`
      SELECT v.dateAdded AS ts, u.username, v.word
      FROM vocabulary v
      LEFT JOIN users u ON u.id = v.userId
      ORDER BY v.dateAdded DESC
      LIMIT 50
    `);

    const items = [
      ...msgRes.rows.map(r => ({
        username: r.username || 'Unknown',
        activity: `Sent a ${r.role || 'user'} message`,
        ts: r.ts
      })),
      ...vocabRes.rows.map(r => ({
        username: r.username || 'Unknown',
        activity: `Added word "${r.word}"`,
        ts: r.ts
      }))
    ]
    .filter(r => r.ts)
    .sort((a, b) => new Date(b.ts) - new Date(a.ts))
    .slice(0, 50)
    .map(r => ({
      username: r.username,
      activity: r.activity,
      timeFormatted: new Date(r.ts).toLocaleString()
    }));

    res.json(items);
  } catch (err) {
    console.error('Recent activity error:', err);
    res.status(500).json({ error: 'Failed to fetch recent activity' });
  }
});

// Helpers (lightweight proxies)
async function getCurrentStreak(userId) {
  try {
    const r = await db.query(
      `SELECT DATE(timestamp) AS d
       FROM messages
       WHERE userId = $1
       GROUP BY DATE(timestamp)
       ORDER BY d DESC`,
      [userId]
    );
    if (!r.rows.length) return 0;
    let streak = 1;
    let last = new Date(r.rows[0].d);
    for (let i = 1; i < r.rows.length; i++) {
      const d = new Date(r.rows[i].d);
      const expected = new Date(last); expected.setDate(expected.getDate() - 1);
      if (d.toDateString() === expected.toDateString()) {
        streak++; last = d;
      } else break;
    }
    return streak;
  } catch {
    return 0;
  }
}

async function getTotalStudyHours(userId) {
  try {
    const r = await db.query(`SELECT COUNT(*)::int AS c FROM messages WHERE userId=$1`, [userId]);
    // heuristic: 20 messages ≈ 1 hour
    return Math.round((r.rows[0].c || 0) / 20);
  } catch {
    return 0;
  }
}

async function calculateAccuracy(userId) {
  try {
    const t = await db.query(`SELECT COUNT(*)::int AS c FROM vocabulary WHERE userId=$1`, [userId]);
    const m = await db.query(`SELECT COUNT(*)::int AS c FROM vocabulary WHERE userId=$1 AND correctCount >= 5`, [userId]);
    const total = t.rows[0].c || 0, mastered = m.rows[0].c || 0;
    return total ? Math.round((mastered / total) * 100) : 0;
  } catch {
    return 0;
  }
}

// Admin API: Progress list for the Progress tab
app.get('/admin/api/progress', ensureAdmin, async (req, res) => {
  try {
    const usersRes = await db.query(`
      SELECT id, email, username, englishLevel, avatarUrl
      FROM users
      ORDER BY id DESC
    `);

    const out = [];
    for (const u of usersRes.rows) {
      // mastered = words with correctCount >= 5
      const vocabRes = await db.query(`
        SELECT
          COUNT(*)::int AS total,
          SUM(CASE WHEN correctCount >= 5 THEN 1 ELSE 0 END)::int AS mastered
        FROM vocabulary
        WHERE userId = $1
      `, [u.id]);
      const total = vocabRes.rows[0].total || 0;
      const mastered = vocabRes.rows[0].mastered || 0;

      const progress = total ? Math.min(Math.round((mastered / 100) * 100), 100) : 0; // keep your scaling
      const hours = await getTotalStudyHours(u.id);
      const accuracy = await calculateAccuracy(u.id);
      const streak = await getCurrentStreak(u.id);

      out.push({
        id: u.id,
        username: u.username || `User ${u.id}`,
        email: u.email || '',
        level: u.englishLevel || 'Beginner',
        learned: mastered,
        hours,
        accuracy,
        streak,
        progress,
        avatarUrl: u.avatarUrl || ''
      });
    }

    res.json(out);
  } catch (err) {
    console.error('Progress API error:', err);
    res.status(500).json({ error: 'Failed to fetch progress' });
  }
});

// Admin API: Vocabulary list (paginated) + users for dropdown
app.get('/admin/api/vocabulary', ensureAdmin, async (req, res) => {
  try {
    const pageSize = 20;
    const page = Math.max(parseInt(req.query.page || '1', 10), 1);
    const offset = (page - 1) * pageSize;

    const totalRes = await db.query(`SELECT COUNT(*)::int AS c FROM vocabulary`);
    const itemsRes = await db.query(`
      SELECT v.id, v.userId, v.word, v.definition, v.dateAdded, v.correctCount, v.difficultyLevel,
             u.username
      FROM vocabulary v
      LEFT JOIN users u ON u.id = v.userId
      ORDER BY v.dateAdded DESC
      LIMIT $1 OFFSET $2
    `, [pageSize, offset]);

    const usersRes = await db.query(`SELECT id, username FROM users ORDER BY id DESC`);

    res.json({
      vocabulary: itemsRes.rows,
      pagination: {
        page,
        pageSize,
        totalItems: totalRes.rows[0].c || 0,
        totalPages: Math.max(1, Math.ceil((totalRes.rows[0].c || 0) / pageSize))
      },
      users: usersRes.rows
    });
  } catch (err) {
    console.error('Vocabulary list error:', err);
    res.status(500).json({ error: 'Failed to fetch vocabulary' });
  }
});

// Admin API: Get one vocabulary
app.get('/admin/api/vocabulary/:id', ensureAdmin, async (req, res) => {
  try {
    const r = await db.query(`SELECT * FROM vocabulary WHERE id=$1`, [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) {
    console.error('Get vocab error:', err);
    res.status(500).json({ error: 'Failed to fetch vocabulary' });
  }
});

// Admin API: Create vocabulary
app.post('/admin/api/vocabulary', ensureAdmin, async (req, res) => {
  try {
    const { userId, word, definition, difficultyLevel, correctCount } = req.body;
    const r = await db.query(`
      INSERT INTO vocabulary (userId, word, definition, difficultyLevel, correctCount)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
    `, [userId, word, definition, difficultyLevel || 1, correctCount || 0]);
    res.json(r.rows[0]);
  } catch (err) {
    console.error('Create vocab error:', err);
    res.status(500).json({ error: 'Failed to create vocabulary' });
  }
});

// Admin API: Update vocabulary
app.put('/admin/api/vocabulary/:id', ensureAdmin, async (req, res) => {
  try {
    const { word, definition, difficultyLevel, correctCount, userId } = req.body;
    await db.query(`
      UPDATE vocabulary
      SET word=$1, definition=$2, difficultyLevel=$3, correctCount=$4, userId=COALESCE($5, userId)
      WHERE id=$6
    `, [word, definition, difficultyLevel || 1, correctCount || 0, userId || null, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Update vocab error:', err);
    res.status(500).json({ error: 'Failed to update vocabulary' });
  }
});

// Admin API: Delete vocabulary
app.delete('/admin/api/vocabulary/:id', ensureAdmin, async (req, res) => {
  try {
    await db.query(`DELETE FROM vocabulary WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('Delete vocab error:', err);
    res.status(500).json({ error: 'Failed to delete vocabulary' });
  }
});

// Admin API: Feedback list
app.get('/admin/api/feedback', ensureAdmin, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT f.id, f.name, f.email, f.subject, f.message, f.userId, f.status, f.dateSubmitted
      FROM feedback f
      ORDER BY f.dateSubmitted DESC
      LIMIT 200
    `);
    res.json(r.rows);
  } catch (err) {
    console.error('Feedback list error:', err);
    res.status(500).json({ error: 'Failed to fetch feedback' });
  }
});

// Admin API: Feedback details
app.get('/admin/api/feedback/:id', ensureAdmin, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT f.*, u.username, u.email AS "userEmail"
      FROM feedback f
      LEFT JOIN users u ON u.id = f.userId
      WHERE f.id = $1
    `, [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (err) {
    console.error('Feedback details error:', err);
    res.status(500).json({ error: 'Failed to fetch feedback details' });
  }
});

// Admin API: Update feedback status
app.put('/admin/api/feedback/:id', ensureAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    await db.query(`UPDATE feedback SET status=$1 WHERE id=$2`, [status, req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Feedback update error:', err);
    res.status(500).json({ error: 'Failed to update feedback' });
  }
});

// Admin API: Delete feedback
app.delete('/admin/api/feedback/:id', ensureAdmin, async (req, res) => {
  try {
    await db.query(`DELETE FROM feedback WHERE id=$1`, [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Feedback delete error:', err);
    res.status(500).json({ error: 'Failed to delete feedback' });
  }
});

// Admin API: subscription plans
app.get('/admin/api/subscription-plans', ensureAdmin, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT
        id,
        name,
        description,
        COALESCE(price, 0)::float AS price,
        COALESCE(billing_interval, 'monthly') AS "billingInterval",
        COALESCE(is_active, true) AS "isActive",
        features
      FROM subscription_plans
      ORDER BY "isActive" DESC, price ASC, id ASC
    `);

    const plans = rows.map(p => ({
      ...p,
      features: (() => { try { return JSON.parse(p.features || '[]'); } catch { return p.features || []; } })()
    }));

    res.json(plans);
  } catch (e) {
    console.error('plans error', e);
    res.json([]); // graceful empty (prevents 500 in Admin UI)
  }
});


// Admin API: subscriptions (joined)
app.get('/admin/api/subscriptions', ensureAdmin, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT
        s.id,
        s.userid AS "userId",
        u.username,
        u.email,
        s.planid AS "planId",
        p.name AS "planName",
        COALESCE(p.price, 0)::float AS price,
        p.billing_interval AS "billingInterval",
        COALESCE(s.status, 'unknown') AS status,
        s.startdate AS "startDate",
        s.enddate AS "currentPeriodEnd",
        COALESCE(s.cancelatperiodend, false) AS "cancelAtPeriodEnd",
        s.stripecustomerid AS "stripeCustomerId",
        s.stripesubscriptionid AS "stripeSubscriptionId"
      FROM subscriptions s
      LEFT JOIN users u ON u.id = s.userid
      LEFT JOIN subscription_plans p ON p.id = s.planid
      ORDER BY s.startdate DESC NULLS LAST, s.id DESC
      LIMIT 500
    `);
    res.json(r.rows || []);
  } catch (e) {
    console.error('subscriptions error', e);
    res.json([]); // graceful empty
  }
});


// Admin API: subscription details
app.get('/admin/api/subscriptions/:id', ensureAdmin, async (req, res) => {
  try {
    const r = await db.query(`
      SELECT
        s.*,
        u.username,
        u.email,
        p.name AS "planName",
        COALESCE(p.price, 0)::float AS price,
        COALESCE(p.billing_interval, 'monthly') AS "billingInterval",
        s.enddate AS "currentPeriodEnd",
        s.stripecustomerid AS "stripeCustomerId",
        s.stripesubscriptionid AS "stripeSubscriptionId"
      FROM subscriptions s
      LEFT JOIN users u ON u.id = s.userid
      LEFT JOIN subscription_plans p ON p.id = s.planid
      WHERE s.id = $1
    `, [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch (e) {
    console.error('subscription detail error', e);
    res.status(500).json({ error: 'Failed to load subscription' });
  }
});

// Admin API: update subscription status / cancel flag
app.put('/admin/api/subscriptions/:id', ensureAdmin, async (req, res) => {
  try {
    const { status, cancelAtPeriodEnd } = req.body;
    await db.query(`
      UPDATE subscriptions
      SET status = COALESCE($1, status),
          cancelatperiodend = COALESCE($2, cancelatperiodend)
      WHERE id = $3
    `, [status || null, (typeof cancelAtPeriodEnd === 'boolean') ? cancelAtPeriodEnd : null, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    console.error('subscription update error', e);
    res.status(500).json({ error: 'Failed to update subscription' });
  }
});

// Admin API: subscription stats
app.get('/admin/api/subscription-stats', ensureAdmin, async (req, res) => {
  try {
    // Active + normalized MRR (yearly -> /12)
    const activeRes = await db.query(`
      SELECT
        COUNT(*)::int AS active,
        COALESCE(SUM(
          CASE WHEN p.billing_interval = 'yearly' THEN (p.price::float / 12.0)
               ELSE p.price::float END
        ), 0)::float AS mrr
      FROM subscriptions s
      LEFT JOIN subscription_plans p ON p.id = s.planid
      WHERE COALESCE(s.status, 'unknown') = 'active'
        AND (COALESCE(s.cancelatperiodend, false) = false OR COALESCE(s.enddate, NOW() + INTERVAL '1 day') > NOW())
    `);

    // Churn in last 30 days (conservative if DB empty)
    const churnNumRes = await db.query(`
      SELECT COUNT(*)::int AS c
      FROM subscriptions
      WHERE COALESCE(status,'unknown') IN ('canceled','expired')
        AND ( (dateupdated IS NOT NULL AND dateupdated >= NOW() - INTERVAL '30 days')
           OR (enddate     IS NOT NULL AND enddate     >= NOW() - INTERVAL '30 days') )
    `);
    const cohortRes = await db.query(`
      SELECT COUNT(*)::int AS c
      FROM subscriptions
      WHERE startdate <= NOW() - INTERVAL '30 days'
        AND COALESCE(status,'unknown') = 'active'
    `);
    const churn30 = cohortRes.rows[0].c ? Math.round((churnNumRes.rows[0].c / cohortRes.rows[0].c) * 100) : 0;

    // Active by plan
    const byPlanRes = await db.query(`
      SELECT s.planid AS "planId", COUNT(*)::int AS count
      FROM subscriptions s
      WHERE COALESCE(s.status,'unknown') = 'active'
      GROUP BY s.planid
    `);
    const byPlan = {};
    byPlanRes.rows.forEach(r => { byPlan[r.planId] = { count: r.count }; });

    res.json({
      active: activeRes.rows[0].active || 0,
      mrr:    activeRes.rows[0].mrr    || 0,
      churn30,
      byPlan
    });
  } catch (e) {
    console.error('subscription stats error', e);
    res.json({ active: 0, mrr: 0, churn30: 0, byPlan: {} }); // no 500s
  }
});

// Admin API: Grant premium to user
app.post('/admin/api/users/:userId/grant-premium', ensureAdmin, async (req, res) => {
  console.log('========================================');
  console.log('[Grant Premium] ENDPOINT HIT!');
  console.log('[Grant Premium] Method:', req.method);
  console.log('[Grant Premium] Path:', req.path);
  console.log('[Grant Premium] Session isAdmin:', req.session?.isAdmin);
  console.log('========================================');
  try {
    console.log('[Grant Premium] Request for user:', req.params.userId, 'Body:', req.body);
    const userId = parseInt(req.params.userId);
    const { planId, durationMonths = 12 } = req.body;

    // Check if user exists
    console.log('[Grant Premium] Checking if user exists...');
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      console.log('[Grant Premium] User not found');
      return res.status(404).json({ error: 'User not found' });
    }
    console.log('[Grant Premium] User found:', userResult.rows[0].username);

    // Check if user already has active premium subscription
    console.log('[Grant Premium] Checking for existing active subscriptions...');
    const existingSubResult = await db.query(`
      SELECT COUNT(*) as count FROM subscriptions
      WHERE userid = $1 AND status = 'active'
    `, [userId]);

    if (existingSubResult.rows[0].count > 0) {
      console.log('[Grant Premium] User already has active premium subscription');
      return res.status(400).json({
        error: 'User already has an active premium subscription',
        message: 'This user already has premium access. You cannot grant premium to a user who already has it.'
      });
    }
    console.log('[Grant Premium] No existing active subscriptions found');

    // Get plan or use first available plan
    let selectedPlanId = planId;
    if (!selectedPlanId) {
      console.log('[Grant Premium] No planId provided, finding first active plan...');
      const planResult = await db.query(`
        SELECT id FROM subscription_plans
        WHERE is_active = true
        ORDER BY price ASC
        LIMIT 1
      `);
      if (planResult.rows.length > 0) {
        selectedPlanId = planResult.rows[0].id;
        console.log('[Grant Premium] Using plan:', selectedPlanId);
      } else {
        console.log('[Grant Premium] No active plans found, using plan ID 2 (Premium Monthly) as fallback');
        selectedPlanId = 2; // Fallback to Premium Monthly plan
      }
    }

    // Calculate dates
    const now = new Date();
    const endDate = new Date();
    endDate.setMonth(endDate.getMonth() + durationMonths);
    console.log('[Grant Premium] Creating subscription from', now, 'to', endDate);

    // Create subscription
    await db.query(`
      INSERT INTO subscriptions (
        userid, planid, status, startdate, enddate,
        stripecustomerid, stripesubscriptionid
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      userId,
      selectedPlanId,
      'active',
      now.toISOString(),
      endDate.toISOString(),
      'admin-grant',
      'admin-grant-' + Date.now()
    ]);
    console.log('[Grant Premium] Subscription created successfully');

    // Try to update user subscription status (optional, may not exist)
    try {
      console.log('[Grant Premium] Attempting to update subscriptionStatus column...');
      await db.query('UPDATE users SET subscriptionstatus = $1 WHERE id = $2', ['premium', userId]);
      console.log('[Grant Premium] subscriptionStatus updated');
    } catch (statusError) {
      console.log('[Grant Premium] subscriptionStatus column may not exist, skipping:', statusError.message);
      // Column might not exist, that's ok - subscription record is what matters
    }

    console.log('[Grant Premium] Success!');
    res.json({
      success: true,
      message: 'Premium access granted successfully',
      endDate: endDate.toISOString()
    });
  } catch (e) {
    console.error('[Grant Premium] Error:', e.message, e.stack);
    res.status(500).json({ error: e.message || 'Failed to grant premium access' });
  }
});

// Admin API: Debug endpoint to check subscription plans
app.get('/admin/api/debug/plans', ensureAdmin, async (req, res) => {
  try {
    const plans = await db.query('SELECT * FROM subscription_plans ORDER BY id');
    const activePlans = await db.query('SELECT * FROM subscription_plans WHERE is_active = true ORDER BY id');
    res.json({
      allPlans: plans.rows,
      activePlans: activePlans.rows,
      hasActivePlans: activePlans.rows.length > 0
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin API: Revoke premium from user
app.post('/admin/api/users/:userId/revoke-premium', ensureAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);

    // Check if user exists
    const userResult = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update all active subscriptions to canceled
    await db.query(`
      UPDATE subscriptions
      SET status = 'canceled', enddate = NOW()
      WHERE userid = $1 AND status = 'active'
    `, [userId]);

    // Update user subscription status to free
    await db.query('UPDATE users SET subscriptionstatus = $1 WHERE id = $2', ['free', userId]);

    res.json({
      success: true,
      message: 'Premium access revoked successfully'
    });
  } catch (e) {
    console.error('revoke premium error', e);
    res.status(500).json({ error: 'Failed to revoke premium access' });
  }
});


// Activities Route
app.get('/activities', (req, res) => {
  // Only render the activities page if user is authenticated
  if (!req.isAuthenticated()) {
    return res.redirect('/login');
  }
  
  // Render the activities page with user object
  res.render('activities', { 
    user: req.user 
  });
});

// Subscription routes
app.get('/subscription/plans', ensureAuthenticated, async (req, res) => {
  try {
    const plansResult = await db.query(`
      SELECT * FROM subscription_plans
      WHERE is_active = true
      ORDER BY price ASC
    `);
    const plans = plansResult.rows;
    
    // Parse features JSON
    plans.forEach(plan => {
      try {
        plan.features = JSON.parse(plan.features);
      } catch (err) {
        plan.features = [];
      }
    });
    
    // Get user's current subscription
    const subscriptionResult = await db.query(`
      SELECT s.*, p.name as planName, p.billing_interval
      FROM subscriptions s
      JOIN subscription_plans p ON s.planId = p.id
      WHERE s.userId = $1 AND s.status = 'active'
      ORDER BY s.id DESC LIMIT 1
    `, [req.user.id]);
    const subscription = subscriptionResult.rows[0] || null;
    
    res.render('subscription/plans', {
      user: req.user,
      plans: plans,
      subscription: subscription,
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
      error: null
    });
  } catch (error) {
    console.error('Error getting plans:', error);
    res.render('subscription/plans', {
      user: req.user,
      plans: [],
      subscription: null,
      stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY,
      error: 'Failed to load subscription plans'
    });
  }
});

// Redirect to plans page for upgrade link
app.get('/subscription/upgrade', ensureAuthenticated, (req, res) => {
  res.redirect('/subscription/plans');
});

// Create checkout session
app.post('/subscription/checkout', ensureAuthenticated, async (req, res) => {
  try {
    const { planId } = req.body;
    
    console.log(`Checkout requested for plan: ${planId}, user: ${req.user.id}`);
    
    if (!planId) {
      return res.status(400).json({ error: 'Plan ID is required' });
    }
    
    // Validate plan exists
    const planResult = await db.query('SELECT * FROM subscription_plans WHERE id = $1', [planId]);
    const plan = planResult.rows[0];
    if (!plan) {
      console.log(`Plan not found: ${planId}`);
      return res.status(404).json({ error: 'Plan not found' });
    }
    
    console.log(`Plan found: ${plan.name}, price: ${plan.price}`);
    
    // Set up success and cancel URLs
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    const successUrl = `${baseUrl}/subscription/success?session_id={CHECKOUT_SESSION_ID}`;
    const cancelUrl = `${baseUrl}/subscription/plans`;
    
    console.log(`Success URL: ${successUrl}`);
    console.log(`Cancel URL: ${cancelUrl}`);
    
    // Create checkout session
    const session = await stripeService.createCheckoutSession(
      req.user.id,
      planId,
      successUrl,
      cancelUrl
    );
    
    if (!session) {
      throw new Error('Failed to create session');
    }
    
    console.log(`Checkout session created: ${session.id}`);
    
    // Return checkout URL
    res.json({ 
      success: true, 
      sessionId: session.id,
      url: session.url 
    });
  } catch (error) {
    console.error('Error creating checkout:', error);
    res.status(500).json({ 
      error: 'Failed to create checkout session', 
      details: error.message 
    });
  }
});

// Handle successful checkout
app.get('/subscription/success', ensureAuthenticated, async (req, res) => {
  try {
    const { session_id } = req.query;
    
    if (!session_id) {
      return res.redirect('/subscription/plans');
    }
    
    // Retrieve session from Stripe
    const session = await stripe.checkout.sessions.retrieve(session_id, {
      expand: ['subscription']
    });
    
    // Verify that this is for the current user
    if (session.metadata.userId != req.user.id) {
      return res.status(403).redirect('/subscription/plans');
    }
    
    // Create subscription in our database
    await stripeService.createSubscription(session);
    
    // Redirect to success page
    res.render('subscription/success', {
      user: req.user,
      planName: session.metadata.planName
    });
  } catch (error) {
    console.error('Error handling success:', error);
    res.redirect('/subscription/plans?error=payment-processing');
  }
});

// Handle webhooks from Stripe
// This must use express.raw middleware to get the raw body for signature verification
app.post('/subscription/webhook', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  try {
    // Verify webhook signature
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
    
    // Handle specific events
    switch (event.type) {
      case 'checkout.session.completed':
        const session = event.data.object;
        await stripeService.createSubscription(session);
        break;
        
      case 'invoice.paid':
        await handleInvoicePaid(event.data.object);
        break;
        
      case 'customer.subscription.deleted':
        await handleSubscriptionCanceled(event.data.object);
        break;
    }
    
    res.json({received: true});
  } catch (error) {
    console.error('Webhook error:', error);
    res.status(400).send(`Webhook Error: ${error.message}`);
  }
});

// Webhook handler for paid invoice (renewal)
async function handleInvoicePaid(invoice) {
  try {
    // Find subscription in our database
    const subscriptionResult = await db.query(`
      SELECT * FROM subscriptions 
      WHERE stripeSubscriptionId = $1
    `, [invoice.subscription]);
    const subscription = subscriptionResult.rows[0];
    
    if (!subscription) return;
    
    // Update subscription end date
    const endDate = new Date();
    const planResult = await db.query('SELECT * FROM subscription_plans WHERE id = $1', [subscription.planid]);
    const plan = planResult.rows[0];
      
    if (plan.billing_interval === 'monthly') {
      endDate.setMonth(endDate.getMonth() + 1);
    } else {
      endDate.setFullYear(endDate.getFullYear() + 1);
    }
    
    await db.query(`
      UPDATE subscriptions
      SET enddate = $1, status = 'active'
      WHERE id = $2
    `, [endDate.toISOString(), subscription.id]);

    // Ensure user status is premium
    await db.query('UPDATE users SET subscriptionstatus = $1 WHERE id = $2', ['premium', subscription.userid]);
  } catch (error) {
    console.error('Error handling invoice payment:', error);
  }
}

// Webhook handler for canceled subscription
async function handleSubscriptionCanceled(subscription) {
  try {
    // Find subscription in our database
    const dbSubscriptionResult = await db.query(`
      SELECT * FROM subscriptions 
      WHERE stripeSubscriptionId = $1
    `, [subscription.id]);
    const dbSubscription = dbSubscriptionResult.rows[0];
    
    if (!dbSubscription) return;
    
    // Update subscription status
    await db.query(`
      UPDATE subscriptions 
      SET status = 'canceled'
      WHERE id = $1
    `, [dbSubscription.id]);
    
    // Update user status to free
    await db.query('UPDATE users SET subscriptionstatus = $1 WHERE id = $2', ['free', dbSubscription.userid]);
  } catch (error) {
    console.error('Error handling subscription cancellation:', error);
  }
}

// Helper function for relative time formatting
function formatRelativeTime(date) {
  const now = new Date();
  const diffMs = now - date;
  const diffSecs = Math.floor(diffMs / 1000);
  const diffMins = Math.floor(diffSecs / 60);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  
  if (diffSecs < 60) {
    return 'Just now';
  } else if (diffMins < 60) {
    return `${diffMins} minute${diffMins === 1 ? '' : 's'} ago`;
  } else if (diffHours < 24) {
    return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  } else if (diffDays < 30) {
    return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
  } else {
    return date.toLocaleDateString();
  }
}

// Performance monitoring endpoint (admin only)
app.get('/api/admin/performance', ensureAdmin, async (req, res) => {
  try {
    // Get database statistics
    const userCountResult = await db.query('SELECT COUNT(*) as count FROM users');
    const messageCountResult = await db.query('SELECT COUNT(*) as count FROM messages');
    const vocabCountResult = await db.query('SELECT COUNT(*) as count FROM vocabulary');
    const subscriptionCountResult = await db.query('SELECT COUNT(*) as count FROM subscriptions WHERE status = $1', ['active']);
    
    const dbStats = {
      users: parseInt(userCountResult.rows[0].count),
      messages: parseInt(messageCountResult.rows[0].count),
      vocabulary: parseInt(vocabCountResult.rows[0].count),
      subscriptions: parseInt(subscriptionCountResult.rows[0].count)
    };
    
    res.json({
      database: dbStats,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Performance monitoring error:', error);
    res.status(500).json({ error: 'Failed to get performance stats' });
  }
});

// Crossword Activity (Free: 1/day, Premium: unlimited)
app.get('/crossword',
  ensureAuthenticated,
  (req, res) => {
    res.render('crossword', { user: req.user, csrfToken: req.csrfToken() });
  }
);

// Crossword generation is now handled by premiumRoutes.js which has better intersection logic



// Production CSRF error handling
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    // Log security incident for monitoring
    console.warn('CSRF Attack Attempt Blocked:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      timestamp: new Date().toISOString(),
      userId: req.user ? req.user.id : 'anonymous'
    });
    
    // Handle CSRF errors appropriately
    if (req.path.startsWith('/api/')) {
      // API endpoints return JSON error
      return res.status(403).json({ 
        error: 'Invalid CSRF token',
        code: 'CSRF_TOKEN_MISMATCH'
      });
    } else {
      // Web pages redirect to login with error message
      return res.redirect('/login?error=security');
    }
  }
  
  // Pass other errors to default handler
  next(err);
});

// Use main routes and premium routes
app.use(mainRoutes);
app.use(premiumRoutes);

// API routes for premium features.
// Crossword generation is a FREE feature (1 puzzle/day, enforced inside the
// route itself), so authenticated non-premium users must be able to reach it.
// This mount handles ONLY the crossword endpoint and must come before the
// premium-gated mount below — otherwise ensurePremium redirects free users to
// /subscription/plans (an HTML page), which the crossword page's fetch would
// follow and then fail to parse as JSON.
app.use('/api/premium', ensureAuthenticated, (req, res, next) => {
  if (req.method === 'POST' && req.path === '/crossword/generate') {
    return premiumRoutes(req, res, next);
  }
  next();
});
app.use('/api/premium', ensureAuthenticated, ensurePremium, premiumRoutes);


// Routes for the privacy policy
app.get('/privacy-policy', (req, res) => {
  res.render('privacy-policy', { 
    user: req.user 
  });
});

// Start Server
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Chrome Extension API endpoints available at:');
  console.log('  - GET  /api/extension/auth-status');
  console.log('  - GET  /api/extension/vocab-count');
  console.log('  - GET  /api/extension/stats');
  console.log('  - POST /api/extension/define-word');
  console.log('  - POST /api/extension/add-word');
  console.log('  - GET  /api/extension/recent-words');
  console.log('  - GET  /api/extension/lookup/:word');
});
