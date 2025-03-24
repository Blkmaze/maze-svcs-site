const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../app');
const User = require('../model.user');

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  await User.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
});

describe('🔐 Auth Flow', () => {
  let refreshToken = '';
  let accessToken = '';

  it('registers a new user', async () => {
    const res = await request(app).post('/register').send({
      username: 'jt_test',
      password: 'secure123'
    });
    expect(res.statusCode).toBe(201);
  });

  it('logs in the user and returns tokens', async () => {
    const res = await request(app).post('/login').send({
      username: 'jt_test',
      password: 'secure123'
    });
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();

    accessToken = res.body.accessToken;
    refreshToken = res.body.refreshToken;
  });

  it('accesses protected route with token', async () => {
    const res = await request(app)
      .get('/protected')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toMatch(/Welcome/);
  });

  it('refreshes tokens', async () => {
    const res = await request(app).post('/refresh').send({
      refreshToken
    });
    expect(res.statusCode).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
  });
});
