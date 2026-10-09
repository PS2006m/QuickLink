const { MongoMemoryServer } = require('mongodb-memory-server');

let mongod;
let app;
let mongoose;
let Url;

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  process.env.MONGO_URI = mongod.getUri('quicklink_test');
  process.env.NODE_ENV = 'test';
  process.env.SESSION_SECRET = 'test-secret';
  delete process.env.GOOGLE_API_KEY; // make sure the safe-browsing check is skipped in tests

  // server.js reads MONGO_URI / connects on require, so env must be set first.
  app = require('../server');
  mongoose = require('mongoose');
  Url = require('../models/Url');

  // Wait for mongoose to finish connecting before running any requests.
  await new Promise((resolve, reject) => {
    if (mongoose.connection.readyState === 1) return resolve();
    mongoose.connection.once('open', resolve);
    mongoose.connection.once('error', reject);
  });
});

afterAll(async () => {
  await mongoose.connection.close();
  await mongod.stop();
});

const request = require('supertest');

function uniqueEmail(prefix) {
  return `${prefix}_${Date.now()}_${Math.floor(Math.random() * 100000)}@test.com`;
}

describe('Auth flows', () => {
  test('signup auto-logs-in: session cookie lets the next request hit /dashboard without re-login', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('signup');

    const signupRes = await agent
      .post('/signup')
      .type('form')
      .send({ email, password: 'password123' });

    expect(signupRes.status).toBe(302);
    expect(signupRes.headers.location).toBe('/dashboard');

    const dashRes = await agent.get('/dashboard');
    expect(dashRes.status).toBe(200);
    expect(dashRes.text).toContain('Your URLs');
  });

  test('duplicate signup returns 409 with an error message shown', async () => {
    const email = uniqueEmail('dup');
    const agent1 = request.agent(app);
    const first = await agent1.post('/signup').type('form').send({ email, password: 'password123' });
    expect(first.status).toBe(302);

    const agent2 = request.agent(app);
    const second = await agent2.post('/signup').type('form').send({ email, password: 'otherpassword' });
    expect(second.status).toBe(409);
    expect(second.text).toMatch(/already be used/i);
  });

  test('login with wrong password returns 401', async () => {
    const email = uniqueEmail('wrongpw');
    const signupAgent = request.agent(app);
    await signupAgent.post('/signup').type('form').send({ email, password: 'correctpassword' });

    const loginAgent = request.agent(app);
    const res = await loginAgent.post('/login').type('form').send({ email, password: 'wrongpassword' });
    expect(res.status).toBe(401);
    expect(res.text).toMatch(/incorrect/i);
  });

  test('GET /dashboard without a session redirects to /login', async () => {
    const res = await request(app).get('/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('POST /shorten without a session does not crash (redirects, not 500)', async () => {
    const res = await request(app)
      .post('/shorten')
      .type('form')
      .send({ originalUrl: 'https://example.com' });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/login');
  });

  test('signup with a missing password does not crash (400, not 500)', async () => {
    const email = uniqueEmail('nopw');
    const res = await request(app).post('/signup').type('form').send({ email });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/valid email and password/i);
  });

  test('login with a missing password does not crash (401, not 500)', async () => {
    const email = uniqueEmail('loginnopw');
    await request(app).post('/signup').type('form').send({ email, password: 'password123' });

    const res = await request(app).post('/login').type('form').send({ email });
    expect(res.status).toBe(401);
    expect(res.text).toMatch(/incorrect/i);
  });

  test('signup with a different casing of an already-registered email is rejected as a duplicate (409)', async () => {
    const email = uniqueEmail('caseDup');
    const agent1 = request.agent(app);
    const first = await agent1.post('/signup').type('form').send({ email, password: 'password123' });
    expect(first.status).toBe(302);

    const agent2 = request.agent(app);
    const mixedCaseEmail = email.toUpperCase();
    const second = await agent2.post('/signup').type('form').send({ email: mixedCaseEmail, password: 'otherpassword' });
    expect(second.status).toBe(409);
    expect(second.text).toMatch(/already be used/i);
  });

  test('login succeeds with a different casing than the email used at signup', async () => {
    const email = uniqueEmail('caseLogin');
    const signupAgent = request.agent(app);
    const signupRes = await signupAgent.post('/signup').type('form').send({ email, password: 'password123' });
    expect(signupRes.status).toBe(302);

    const loginAgent = request.agent(app);
    const res = await loginAgent.post('/login').type('form').send({ email: email.toUpperCase(), password: 'password123' });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');
  });
});

describe('Dashboard behaviour', () => {
  test('deleting one URL preserves another URL\'s click count (regression for the dashboard rebuild bug)', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('clicks');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    await agent.post('/shorten').type('form').send({ originalUrl: 'https://example.com/keep' });
    await agent.post('/shorten').type('form').send({ originalUrl: 'https://example.com/remove' });

    const docs = await Url.find({ userEmail: email }).sort({ createdAt: 1 });
    expect(docs.length).toBe(2);
    const keepDoc = docs.find(d => d.originalUrl === 'https://example.com/keep');
    const removeDoc = docs.find(d => d.originalUrl === 'https://example.com/remove');

    // Click the "keep" link once.
    const clickRes = await agent.get(`/${keepDoc.shortId}`);
    expect(clickRes.status).toBe(302);
    expect(clickRes.headers.location).toBe('https://example.com/keep');

    // Delete the other link.
    const delRes = await agent.post(`/delete/${removeDoc.shortId}`);
    expect(delRes.status).toBe(302);
    expect(delRes.headers.location).toBe('/dashboard');

    const keepAfter = await Url.findOne({ shortId: keepDoc.shortId });
    expect(keepAfter).not.toBeNull();
    expect(keepAfter.clicks).toBe(1);

    const removeAfter = await Url.findOne({ shortId: removeDoc.shortId });
    expect(removeAfter).toBeNull();
  });

  test('IDOR fix: user B cannot delete user A\'s link', async () => {
    const agentA = request.agent(app);
    const emailA = uniqueEmail('userA');
    await agentA.post('/signup').type('form').send({ email: emailA, password: 'password123' });
    await agentA.post('/shorten').type('form').send({ originalUrl: 'https://example.com/a-link' });

    // Emails are normalized to lowercase at signup/login, so stored userEmail
    // values are lowercase even though the fixture email has mixed case.
    const docA = await Url.findOne({ userEmail: emailA.toLowerCase(), originalUrl: 'https://example.com/a-link' });
    expect(docA).not.toBeNull();

    const agentB = request.agent(app);
    const emailB = uniqueEmail('userB');
    await agentB.post('/signup').type('form').send({ email: emailB, password: 'password123' });

    // User B attempts to delete user A's link by guessing/knowing the shortId.
    const delRes = await agentB.post(`/delete/${docA.shortId}`);
    expect(delRes.status).toBe(302); // handler redirects to B's dashboard, doesn't error
    expect(delRes.headers.location).toBe('/dashboard');

    const stillThere = await Url.findOne({ shortId: docA.shortId });
    expect(stillThere).not.toBeNull();
    expect(stillThere.userEmail).toBe(emailA.toLowerCase());
  });
});

describe('URL validation on /shorten', () => {
  test('empty originalUrl does not crash with a 500 / stack trace, returns 400 with a clear error', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('emptyurl');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.post('/shorten').type('form').send({ originalUrl: '' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/valid http/i);
    expect(res.text).not.toMatch(/ValidationError/i);
    expect(res.text).not.toMatch(/at Url\.create/i);
  });

  test('missing originalUrl field does not crash, returns 400', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('nourl');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.post('/shorten').type('form').send({});
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/valid http/i);
  });

  test('malformed URL ("notaurl") is rejected with 400, not stored', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('malformed');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.post('/shorten').type('form').send({ originalUrl: 'notaurl' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/valid http/i);

    const stored = await Url.findOne({ userEmail: email, originalUrl: 'notaurl' });
    expect(stored).toBeNull();
  });

  test('javascript: scheme URL is rejected with 400, not stored', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('jsurl');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.post('/shorten').type('form').send({ originalUrl: 'javascript:alert(1)' });
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/valid http/i);

    const stored = await Url.findOne({ userEmail: email, originalUrl: 'javascript:alert(1)' });
    expect(stored).toBeNull();
  });

  test('a valid https:// URL is still accepted', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('validurl');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.post('/shorten').type('form').send({ originalUrl: 'https://example.com/ok' });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');

    const stored = await Url.findOne({ userEmail: email, originalUrl: 'https://example.com/ok' });
    expect(stored).not.toBeNull();
  });
});

describe('POST /delete/:id redirects instead of re-rendering in place', () => {
  test('deleting a link redirects to /dashboard (avoids form-resubmission prompt)', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('delredirect');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });
    await agent.post('/shorten').type('form').send({ originalUrl: 'https://example.com/del-me' });

    const doc = await Url.findOne({ userEmail: email, originalUrl: 'https://example.com/del-me' });
    expect(doc).not.toBeNull();

    const res = await agent.post(`/delete/${doc.shortId}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/dashboard');

    const gone = await Url.findOne({ shortId: doc.shortId });
    expect(gone).toBeNull();
  });
});

describe('Bfcache defense on dashboard', () => {
  test('dashboard HTML includes a pageshow listener that reloads on bfcache restore', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('bfcache');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.get('/dashboard');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/pageshow/);
    expect(res.text).toMatch(/event\.persisted/);
    expect(res.text).toMatch(/location\.reload\(\)/);
  });
});

describe('Cache headers', () => {
  test('GET /dashboard sends no-store cache headers', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('cache');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.get('/dashboard');
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['cache-control']).toMatch(/no-cache/);
    expect(res.headers['pragma']).toBe('no-cache');
  });

  test('GET /login sends no-store cache headers', async () => {
    const res = await request(app).get('/login');
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['pragma']).toBe('no-cache');
  });

  test('GET /logout sends no-store cache headers', async () => {
    const agent = request.agent(app);
    const email = uniqueEmail('logoutcache');
    await agent.post('/signup').type('form').send({ email, password: 'password123' });

    const res = await agent.get('/logout');
    expect(res.headers['cache-control']).toMatch(/no-store/);
    expect(res.headers['pragma']).toBe('no-cache');
  });
});
