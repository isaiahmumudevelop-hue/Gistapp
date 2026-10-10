const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: (process.env.DATABASE_URL || '').replace('sslmode=require', 'sslmode=require&uselibpqcompat=true'),
  max: 10,
  idleTimeoutMillis: 20000,
  connectionTimeoutMillis: 30000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000
});

pool.on('error', (err) => {
  // Neon drops idle connections — log but do not crash
  console.warn('⚠️  PG warn:', err.message);
  if (err.message.includes('terminated') || err.message.includes('timeout')){
    // reconnect soon — nothing else needed; pool handles new connections automatically
  }
});

module.exports = pool;
