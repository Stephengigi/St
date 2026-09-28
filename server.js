const express = require('express');
const rateLimit = require('express-rate-limit');
const ping = require('ping');
const dns = require('dns');
const whois = require('whois');
const sslChecker = require('ssl-checker');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const app = express();
const PORT = process.env.PORT || 3000;

// 托管静态前端文件（public目录）
app.use(express.static('public'));
app.use(express.json());

// 接口限流：同一个IP 1分钟最多5次探测请求
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: "请求过于频繁，请稍后重试。单IP一分钟最多5次探测" }
});
app.use('/api', apiLimiter);

// 简单输入合法性校验
function validateTarget(target) {
  const reg = /^[a-zA-Z0-9\.\-\:]+$/;
  return reg.test(target);
}

// Ping接口
app.post('/api/ping', async (req, res) => {
  const { host, count = 4 } = req.body;
  if (!validateTarget(host)) return res.json({ error: "非法目标地址" });
  try {
    const result = await ping.promise.probe(host, {
      timeout: 2,
      min_reply: Number(count)
    });
    res.json(result);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// DNS查询接口
app.post('/api/dns', async (req, res) => {
  const { host, type = 'A' } = req.body;
  if (!validateTarget(host)) return res.json({ error: "非法目标地址" });
  try {
    const fnMap = {
      A: dns.resolve4,
      AAAA: dns.resolve6,
      CNAME: dns.resolveCname,
      MX: dns.resolveMx,
      NS: dns.resolveNs,
      TXT: dns.resolveTxt
    };
    const records = await fnMap[type](host);
    res.json(records);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// WHOIS查询
app.post('/api/whois', async (req, res) => {
  const { host } = req.body;
  if (!validateTarget(host)) return res.json({ error: "非法目标地址" });
  whois.lookup(host, (err, data) => {
    if (err) return res.json({ error: err.message });
    res.json({ data });
  });
});

// SSL证书检测
app.post('/api/ssl', async (req, res) => {
  const { host } = req.body;
  if (!validateTarget(host)) return res.json({ error: "非法目标地址" });
  try {
    const cert = await sslChecker(host, 443);
    res.json(cert);
  } catch (e) {
    res.json({ error: e.message });
  }
});

// TCP端口探测，最多3个端口
app.post('/api/tcpport', async (req, res) => {
  const { host, ports } = req.body;
  if (!validateTarget(host)) return res.json({ error: "非法目标地址" });
  const portList = ports.split(',').slice(0,3);
  const net = require('net');
  const ret = [];
  for(const p of portList){
    const port = parseInt(p);
    if(isNaN(port)) continue;
    const promise = new Promise((resolve)=>{
      const sock = new net.Socket();
      sock.setTimeout(2000);
      sock.on('connect', ()=>{ sock.destroy(); resolve({port, open:true}); })
      sock.on('timeout', ()=>{ sock.destroy(); resolve({port, open:false}); })
      sock.on('error', ()=>{ sock.destroy(); resolve({port, open:false}); })
      sock.connect(port, host);
    })
    ret.push(await promise);
  }
  res.json(ret);
});

// HTTP连通检测
app.post('/api/http', async (req, res) => {
  const { url } = req.body;
  try{
    const resp = await fetch(url, {timeout:10000});
    const headers = Object.fromEntries(resp.headers);
    res.json({status:resp.status, headers});
  }catch(e){
    res.json({error:e.message});
  }
});

// 获取客户端IP（删掉ip包依赖）
app.get('/api/myip', (req,res)=>{
  const ipAddr = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  res.json({ip:ipAddr});
})

// 启动服务
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
