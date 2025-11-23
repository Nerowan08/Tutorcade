/* Tutorcade REST API — Node 18 / Express 4 (DB-only, transactional tasks)
   必要环境变量：
   - DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME
   - JWT_SECRET
   - CF_TURNSTILE_SECRET 或 TURNSTILE_SECRET
   - CORS_ORIGINS（可选，逗号分隔白名单，如 https://yourdomain.com,https://www.yourdomain.com）
   - DEV_BYPASS_TURNSTILE（可选，本地调试可设为 true）
*/

require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const bcrypt  = require('bcrypt');
const jwt     = require('jsonwebtoken');
const mysql   = require('mysql2/promise');
const path    = require('path');
const https   = require('https');

const app = express();

/* ---------- 安全响应头（轻量版，无需新依赖） ---------- */
app.use((req,res,next)=>{
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Permissions-Policy','geolocation=(), microphone=(), camera=()');
  // CSP：允许 Turnstile 脚本 & 本页内联脚本；如未来拆分成外链 JS 可去掉 'unsafe-inline'
  res.setHeader('Content-Security-Policy',
    "default-src 'self';" +
    "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com;" +
    "style-src 'self' 'unsafe-inline';" +
    "img-src 'self' data:;" +
    "connect-src 'self';" +
    "frame-ancestors 'none';" +
    "base-uri 'self';" +
    "form-action 'self'");
  next();
});

/* ---------- CORS（生产建议配置 CORS_ORIGINS） ---------- */
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS||'').split(',').map(s=>s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb)=>{
    if(!origin) return cb(null,true);
    if(ALLOWED_ORIGINS.length===0) return cb(null,true); // 未配置则默认允许（便于联调）
    cb(null, ALLOWED_ORIGINS.includes(origin));
  },
  credentials:false,
  allowedHeaders:['Content-Type','Authorization'],
  methods:['GET','POST','PUT','DELETE','OPTIONS']
}));

app.use(express.json());

/* ---------- 静态资源（适度缓存） ---------- */
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=3600');
    }
  }
}));

/* ---------- MySQL ---------- */
const pool = mysql.createPool({
  host            : process.env.DB_HOST,
  port            : +(process.env.DB_PORT || 3306),
  user            : process.env.DB_USER,
  password        : process.env.DB_PASS,
  database        : process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit : 10,
  charset         : 'utf8mb4'
});
const q = (sql, params=[]) => pool.execute(sql, params).then(r=>r[0]);

/* ---------- Turnstile ---------- */
const TURNSTILE_SECRET =
  process.env.CF_TURNSTILE_SECRET
  || process.env.TURNSTILE_SECRET
  || '0x4AAAAAABp1M_QfedaPKTEDQQG6mtDmTuQ'; // <— 你的 Secret Key 作为兜底

const DEV_BYPASS_TURNSTILE = String(process.env.DEV_BYPASS_TURNSTILE||'').toLowerCase()==='true';
console.log('[Boot] Turnstile secret present:', !!TURNSTILE_SECRET, ' DEV_BYPASS_TURNSTILE:', DEV_BYPASS_TURNSTILE);

function clientIP(req){
  return req.headers['cf-connecting-ip']
      || (req.headers['x-forwarded-for']?.split(',')[0])
      || req.headers['x-real-ip']
      || req.socket.remoteAddress
      || '';
}
function verifyTurnstile(token, ip) {
  return new Promise((resolve) => {
    if (DEV_BYPASS_TURNSTILE) return resolve({ success:true, errorCodes:[] });
    if (!TURNSTILE_SECRET)   return resolve({ success:false, errorCodes:['server-misconfigured'] });
    if (!token)              return resolve({ success:false, errorCodes:['missing-token'] });

    const postData = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, remoteip: ip||'' }).toString();
    const options = {
      hostname: 'challenges.cloudflare.com',
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(postData)},
      timeout: 7000
    };
    const reqH = https.request(options, (res) => {
      let data = '';
      res.on('data',(d)=>data+=d);
      res.on('end',()=>{
        try{
          const json = JSON.parse(data);
          resolve({ success: !!json.success, errorCodes: json['error-codes']||[] });
        }catch{ resolve({ success:false, errorCodes:['parse-error'] }); }
      });
    });
    reqH.on('error',()=>resolve({ success:false, errorCodes:['connection-error'] }));
    reqH.on('timeout',()=>{ try{reqH.destroy();}catch{} resolve({ success:false, errorCodes:['timeout'] }); });
    reqH.write(postData); reqH.end();
  });
}

/* ---------- JWT 中间件 ---------- */
function authRequired(req,res,next){
  const token = req.headers.authorization?.split(' ')[1];
  if(!token) return res.status(401).json({msg:'missing token'});
  try{ req.user=jwt.verify(token,process.env.JWT_SECRET); next(); }
  catch{ return res.status(401).json({msg:'invalid token'}); }
}

/* ---------- 工具 ---------- */
const normalize   = s => (s||'').trim();
const normalizeAns= s => (s||'').trim().toLowerCase();
function todayRange() {
  // 使用 DB 时区的“今日”，改成范围条件以命中索引
  const start = 'CURDATE()';
  const end   = 'CURDATE() + INTERVAL 1 DAY';
  return { start, end };
}

/* ---------- 账户：注册 / 登录 / 注销 / 积分 ---------- */
app.post('/api/register', async (req,res)=>{
  const { username, password, cfToken, secQuestion, secAnswer } = req.body || {};
  const { success, errorCodes } = await verifyTurnstile(cfToken, clientIP(req));
  if(!success) return res.status(400).json({msg:'captcha failed', cfErrors:errorCodes});

  const u = normalize(username), p = String(password||'');
  if(!u || !p) return res.status(400).json({msg:'username & password required'});

  try{
    const exists = await q('SELECT 1 FROM users WHERE username=?',[u]);
    if(exists.length) return res.status(409).json({msg:'user exists'});
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'users table missing'});
    throw e;
  }

  const hash = await bcrypt.hash(p, +process.env.BCRYPT_ROUNDS || 10);
  let sq=null, sah=null;
  if (normalize(secQuestion) && normalize(secAnswer)){
    sq  = normalize(secQuestion).slice(0,255);
    sah = await bcrypt.hash(normalizeAns(secAnswer), +process.env.BCRYPT_ROUNDS || 10);
  }

  try{
    await q('INSERT INTO users(username,pass_hash,points,sec_question,sec_answer_hash) VALUES(?,?,0,?,?)',
      [u,hash,sq,sah]);
    res.json({msg:'registered'});
  }catch(e){
    if(e.code==='ER_BAD_FIELD_ERROR') return res.status(400).json({msg:'users table lacks security QA columns'});
    if(e.code==='ER_NO_SUCH_TABLE')  return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});

app.post('/api/login', async (req,res)=>{
  const { username, password, cfToken } = req.body || {};
  const { success, errorCodes } = await verifyTurnstile(cfToken, clientIP(req));
  if(!success) return res.status(400).json({msg:'captcha failed', cfErrors:errorCodes});

  const u = normalize(username), p = String(password||'');
  let user;
  try{
    [user] = await q('SELECT * FROM users WHERE username=?',[u]);
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'users table missing'});
    throw e;
  }
  if(!user) return res.status(401).json({msg:'wrong credentials'});
  if(!await bcrypt.compare(p,user.pass_hash)) return res.status(401).json({msg:'wrong credentials'});

  const token = jwt.sign({id:user.id,username:u},process.env.JWT_SECRET,{expiresIn:'7d'});
  res.json({token,username:u,points:user.points});
});

app.delete('/api/me', authRequired, async (req,res)=>{
  try{
    await q('DELETE FROM users WHERE id=?',[req.user.id]);
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'users table missing'});
    throw e;
  }
  res.json({ok:true});
});
app.get('/api/me/points', authRequired, async (req,res)=>{
  try{
    const [r]=await q('SELECT points FROM users WHERE id=?',[req.user.id]);
    res.json({points:r?.points ?? 0});
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});

/* ---------- 安全问题（设置/查看） ---------- */
app.get('/api/security-question', authRequired, async (req,res)=>{
  try{
    const [u]=await q('SELECT sec_question FROM users WHERE id=?',[req.user.id]);
    res.json({question: u?.sec_question || ''});
  }catch(e){
    if(e.code==='ER_BAD_FIELD_ERROR') return res.json({question:''});
    if(e.code==='ER_NO_SUCH_TABLE')  return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});
app.put('/api/security-question', authRequired, async (req,res)=>{
  const { question, answer } = req.body || {};
  let sq=null, sah=null;
  if (normalize(question) && normalize(answer)) {
    sq  = normalize(question).slice(0,255);
    sah = await bcrypt.hash(normalizeAns(answer), +process.env.BCRYPT_ROUNDS || 10);
  }
  try{
    await q('UPDATE users SET sec_question=?, sec_answer_hash=? WHERE id=?',[sq,sah,req.user.id]);
    res.json({ok:true});
  }catch(e){
    if(e.code==='ER_BAD_FIELD_ERROR') return res.status(400).json({msg:'users table lacks security QA columns'});
    if(e.code==='ER_NO_SUCH_TABLE')  return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});

/* ---------- 找回密码（基于安全问题） ---------- */
app.post('/api/forgot/start', async (req,res)=>{
  const { username, cfToken } = req.body || {};
  const { success, errorCodes } = await verifyTurnstile(cfToken, clientIP(req));
  if(!success) return res.status(400).json({msg:'captcha failed', cfErrors:errorCodes});

  try{
    const [row] = await q('SELECT sec_question FROM users WHERE username=?',[normalize(username)]);
    if(!row || !row.sec_question) return res.status(404).json({msg:'user or security question not found'});
    res.json({question: row.sec_question});
  }catch(e){
    if(e.code==='ER_BAD_FIELD_ERROR') return res.status(404).json({msg:'user or security question not found'});
    if(e.code==='ER_NO_SUCH_TABLE')  return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});

app.post('/api/forgot/verify', async (req,res)=>{
  const { username, answer, newPassword, cfToken } = req.body || {};
  const { success, errorCodes } = await verifyTurnstile(cfToken, clientIP(req));
  if(!success) return res.status(400).json({msg:'captcha failed', cfErrors:errorCodes});

  try{
    const [row] = await q('SELECT id, sec_answer_hash FROM users WHERE username=?',[normalize(username)]);
    if(!row || !row.sec_answer_hash) return res.status(400).json({msg:'security QA not set'});
    const ok = await bcrypt.compare(normalizeAns(answer), row.sec_answer_hash);
    if(!ok) return res.status(401).json({msg:'incorrect answer'});
    const nhash = await bcrypt.hash(String(newPassword||''), +process.env.BCRYPT_ROUNDS || 10);
    await q('UPDATE users SET pass_hash=? WHERE id=?',[nhash,row.id]);
    res.json({ok:true});
  }catch(e){
    if(e.code==='ER_BAD_FIELD_ERROR') return res.status(400).json({msg:'security QA not set'});
    if(e.code==='ER_NO_SUCH_TABLE')  return res.status(503).json({msg:'users table missing'});
    throw e;
  }
});

/* ---------- 新闻（文案与旧版一致） ---------- */
const NEWS=[
  {id:1,title:'2025‑06‑25  Daily task system launched!',desc:'Points are now earned exclusively by completing daily tasks.'},
  {id:2,title:'2025‑06‑20  Tutorcade initial release',desc:'Enjoy learning through play!'}
];
app.get('/api/news', (_req,res)=>res.json(NEWS));

/* ---------- 游戏目录 ---------- */
app.get('/api/games', async (_req,res)=>{
  try{
    const rows = await q('SELECT * FROM games ORDER BY id');
    res.json(rows);
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.json([]); // 若后台未上架游戏则为空
    console.error('[Games] error:', e);
    res.status(500).json({msg:'cannot load games'});
  }
});

/* ---------- 活动记录（严格使用 DB） ---------- */
app.post('/api/activity/start', authRequired, async (req,res)=>{
  const {gameId}=req.body;
  try{
    const [{insertId:id}] = await pool.execute(
      'INSERT INTO sessions(user_id,game_id,start_time) VALUES(?,?,NOW())',
      [req.user.id,gameId]
    );
    res.json({sessionId:id});
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'sessions table missing'});
    console.error('[Activity/start] error:', e);
    res.status(500).json({msg:'cannot start session'});
  }
});
app.post('/api/activity/end', authRequired, async (req,res)=>{
  const {sessionId}=req.body;
  try{
    await q('UPDATE sessions SET end_time=NOW() WHERE id=? AND user_id=?',[sessionId,req.user.id]);
    res.json({ok:true});
  }catch(e){
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'sessions table missing'});
    console.error('[Activity/end] error:', e);
    res.status(500).json({msg:'cannot end session'});
  }
});

/* ---------- 每日任务（原子结算 + 范围查询 + 幂等） ---------- */
const TASKS = [
  {id:'PLAY_ONCE', txt:'Launch any game',          points:5},
  {id:'TEN_MIN',   txt:'Play games for ≥10 min',   points:10}
];

app.get('/api/tasks', authRequired, async (req,res)=>{
  const uid = req.user.id;
  const { start, end } = todayRange(); // SQL 片段（CURDATE() ~ CURDATE()+1）
  const conn = await pool.getConnection();
  try{
    await conn.beginTransaction();

    // 确保今日两条任务行存在
    for(const t of TASKS){
      await conn.execute(
        'INSERT IGNORE INTO user_tasks(user_id,task_id,task_date) VALUES(?, ?, CURDATE())',
        [uid, t.id]
      );
    }

    // 任务1：PLAY_ONCE（今日有任意会话）
    const [r1] = await conn.execute(
      `UPDATE user_tasks ut
       JOIN (
         SELECT 1 AS ok
         FROM sessions
         WHERE user_id=?
           AND start_time >= ${start}
           AND start_time <  ${end}
         LIMIT 1
       ) cond ON cond.ok=1
       SET ut.done=1
       WHERE ut.user_id=? AND ut.task_id='PLAY_ONCE' AND ut.task_date=CURDATE() AND ut.done=0`,
      [uid, uid]
    );
    if (r1.affectedRows > 0) {
      await conn.execute('UPDATE users SET points=points+? WHERE id=?',[5, uid]);
    }

    // 任务2：TEN_MIN（今日累计≥600秒）
    const [[{sec}]] = await conn.execute(
      `SELECT COALESCE(SUM(TIMESTAMPDIFF(SECOND, start_time, COALESCE(end_time, NOW()))),0) AS sec
       FROM sessions
       WHERE user_id=?
         AND start_time >= ${start}
         AND start_time <  ${end}`,
      [uid]
    );
    if (Number(sec) >= 600) {
      const [r2] = await conn.execute(
        `UPDATE user_tasks
         SET done=1
         WHERE user_id=? AND task_id='TEN_MIN' AND task_date=CURDATE() AND done=0`,
        [uid]
      );
      if (r2.affectedRows > 0) {
        await conn.execute('UPDATE users SET points=points+? WHERE id=?',[10, uid]);
      }
    }

    // 汇总状态与当前积分
    const [rows] = await conn.execute(
      `SELECT task_id, done FROM user_tasks WHERE user_id=? AND task_date=CURDATE()`,
      [uid]
    );
    const status = Object.fromEntries(rows.map(r=>[r.task_id, !!r.done]));
    const [[urow]] = await conn.execute('SELECT points FROM users WHERE id=?',[uid]);

    await conn.commit();

    res.json(
      TASKS.map(t=>({id:t.id, text:t.txt, points:t.points, done: !!status[t.id]}))
           .concat([{ userPoints: urow?.points ?? 0 }])
    );
  }catch(e){
    await conn.rollback();
    if(e.code==='ER_NO_SUCH_TABLE') return res.status(503).json({msg:'required tables missing'});
    console.error('[Tasks] error:', e);
    res.status(500).json({msg:'tasks unavailable'});
  }finally{
    conn.release();
  }
});

/* ---------- 健康检查 ---------- */
app.get('/healthz', (_req,res)=>res.status(200).send('ok'));
app.get('/readyz', async (_req,res)=>{
  try{ await q('SELECT 1'); return res.status(200).json({db:true}); }
  catch{ return res.status(503).json({db:false}); }
});

/* ---------- favicon ---------- */
app.get('/favicon.ico', (_req,res)=>res.sendStatus(204));

/* ---------- 启动 ---------- */
const PORT=process.env.PORT||3000;
const server = app.listen(PORT,()=>console.log('Tutorcade API on',PORT));

/* ---------- 优雅关闭 ---------- */
function shutdown(sig){
  console.log(`[${sig}] shutting down...`);
  server.close(async ()=>{
    try{ await pool.end(); }catch{}
    process.exit(0);
  });
}
process.on('SIGTERM',()=>shutdown('SIGTERM'));
process.on('SIGINT', ()=>shutdown('SIGINT'));
