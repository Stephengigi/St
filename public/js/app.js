const express = require('express');
const cors = require('cors');
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const { spawn } = require('child_process');
const app = express();
app.use(cors());
app.use(express.json());
// 适配当前目录结构：app.js 在 public/js 里面
app.use(express.static(__dirname + '/../'));
// 【设置全局DNS服务器，改用国内公共DNS，大幅减少超时】
dns.setServers(['114.114.114.114','223.5.5.5']);
// 端口扫描限流：单目标1分钟最多5次
const rateMap = new Map();
const RATE_LIMIT_COUNT = 5;
const RATE_LIMIT_TIME = 60 * 1000;
function checkRate(host) {
    const now = Date.now();
    if (!rateMap.has(host)) {
        rateMap.set(host, { count: 1, startTime: now });
        return true;
    }
    const item = rateMap.get(host);
    if (now - item.startTime > RATE_LIMIT_TIME) {
        rateMap.set(host, { count: 1, startTime: now });
        return true;
    }
    if (item.count >= RATE_LIMIT_COUNT) return false;
    item.count += 1;
    return true;
}
// 通用fetch封装：兼容超时，不用AbortSignal.timeout
async function safeFetch(url, opt={}, ms=8000){
    const controller = new AbortController();
    const timer = setTimeout(()=>controller.abort(), ms);
    try{
        const res = await fetch(url, { ...opt, signal:controller.signal });
        clearTimeout(timer);
        return res;
    }catch(e){
        clearTimeout(timer);
        throw e;
    }
}
// Ping接口
app.post('/api/ping', (req, res) => {
    const { host } = req.body;
    const cmd = process.platform === 'win32' ? `ping -n 4 ${host}` : `ping -c 4 ${host}`;
    const { exec } = require('child_process');
    exec(cmd, (err, stdout, stderr) => {
        if (err) return res.json({ error: stderr || err.message });
        res.json({ success: true, output: stdout });
    })
});
// DNS查询接口【修复：增加超时Promise，解决长时间timeout卡死】
app.post('/api/dns', async (req, res) => {
    try {
        const { host, recordType } = req.body;
        const typeMap = {
            "A": "A",
            "AAAA": "AAAA",
            "CNAME": "CNAME",
            "MX": "MX",
            "TXT": "TXT"
        };
        const type = typeMap[recordType] || "A";
        const queryPromise = dns.resolve(host, type);
        const timeoutPromise = new Promise((_, reject) => {
            setTimeout(()=>reject("DNS查询超时(5s)"),5000);
        })
        const result = await Promise.race([queryPromise, timeoutPromise]);
        res.json({ success: true, host, recordType, data: result });
    } catch (e) {
        res.json({ error: e.message });
    }
});
// SSL证书检测【内置tls原生实现，不需要第三方包】
app.post('/api/ssl', async (req, res) => {
    try {
        const { host } = req.body;
        const certInfo = await new Promise((resolve, reject) => {
            const socket = tls.connect({
                host: host,
                port: 443,
                servername: host,
                rejectUnauthorized: false
            }, () => {
                const cert = socket.getPeerCertificate();
                socket.destroy();
                resolve(cert);
            });
            socket.setTimeout(5000);
            socket.on('timeout', () => {
                socket.destroy();
                reject("连接超时");
            });
            socket.on('error', err => {
                socket.destroy();
                reject(err.message);
            });
        });
        res.json({
            success: true,
            cert: {
                issuer: certInfo.issuer,
                valid_from: certInfo.valid_from,
                valid_to: certInfo.valid_to,
                subject: certInfo.subject,
                serialNumber: certInfo.serialNumber
            }
        });
    } catch (e) {
        res.json({ error: e.message });
    }
});
// TCP端口探测接口
app.post('/api/portscan', async (req, res) => {
    const { host, ports } = req.body;
    if (!checkRate(host)) {
        return res.json({ error: "请求过于频繁，请稍后重试。单IP一分钟最多5次探测" });
    }
    const resultList = [];
    for (const port of ports) {
        const isOpen = await new Promise((resolve) => {
            const sock = new net.Socket();
            sock.setTimeout(2000);
            sock.on('connect', () => { sock.destroy(); resolve(true); });
            sock.on('error', () => resolve(false));
            sock.on('timeout', () => { sock.destroy(); resolve(false); });
            sock.connect(port, host);
        });
        resultList.push({ port, open: isOpen });
    }
    res.json({ success: true, results: resultList });
});
// HTTP连通检测接口，自动补https，修复Invalid URL，使用safeFetch防卡死
app.post('/api/http', async (req, res) => {
    try {
        let { url } = req.body;
        if (!url.startsWith('http')) {
            url = 'https://' + url;
        }
        const resp = await safeFetch(url, {},5000);
        res.json({ success: true, status: resp.status, url });
    } catch (e) {
        res.json({ error: e.message });
    }
});
// ========== SSE 实时路由追踪【修复：超时改成120秒，适配Windows tracert】==========
app.get('/api/traceroute', (req, res) => {
    const target = req.query.host?.trim();
    if (!target) {
        return res.status(400).json({error: "缺少host参数"});
    }
    // SSE头部
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();
    // Windows: tracert -d，Linux: traceroute -n
    const cmd = process.platform === 'win32' ? 'tracert' : 'traceroute';
    const args = process.platform === 'win32' ? ['-d', target] : ['-n', target];
    const tracer = spawn(cmd, args);
    // 修改：最大超时120秒，tracert完整跑完30跳需要这么久
    const killTimer = setTimeout(()=>{
        tracer.kill();
        res.write(`data: \n---追踪超时(120s)，强制结束---\n\n`);
        res.end();
    },120000);
    tracer.stdout.on('data', (buf) => {
    let text = buf.toString();
    // =========就是这两行，放在回调函数内部=========
    text = text.replace(/\r\n/g, "\n");
    res.write(`data: ${text}\n\n`);
    });
    tracer.stderr.on('data', (buf) => {
        const text = buf.toString();
        res.write(`data: 【stderr】${text}\n\n`);
    });
    tracer.on('close', (code) => {
        clearTimeout(killTimer);
        res.write(`data: \n---追踪完成，退出码:${code}---\n\n`);
        res.end();
    });
    tracer.on('error', (err) => {
        clearTimeout(killTimer);
        res.write(`data: 执行命令失败：${err.message}\n\n`);
        res.end();
    });
    // 前端断开连接时杀掉进程
    req.on('close', ()=>{
        clearTimeout(killTimer);
        tracer.kill();
    })
});
// IP归属地查询接口 - ip.sb国内稳定版，使用safeFetch防卡死
app.post('/api/ipgeo', async (req, res) => {
    try {
        const { host } = req.body;
        const lookupResult = await dns.lookup(host);
        const ip = lookupResult.address;
        const geoResp = await safeFetch(`https://api.ip.sb/geoip/${ip}`,{},8000);
        if(!geoResp.ok){
            return res.json({success:false, error:"归属地外部接口访问失败", ip});
        }
        const geoData = await geoResp.json();
        res.json({
            success:true,
            queryHost: host,
            ip: ip,
            country: geoData.country || "-",
            region: geoData.region || "-",
            city: geoData.city || "-",
            isp: geoData.isp || "-",
            timezone: geoData.timezone || "-"
        })
    }catch(e){
        console.error("ipgeo异常：",e);
        res.json({success:false, error:"异常："+ e.message})
    }
});
// WHOIS域名查询接口
app.post('/api/whois', async (req, res) => {
    try {
        const { domain } = req.body;
        if (!domain) return res.json({error:"域名不能为空"});
        let cleanDomain = domain.replace(/^https?:\/\//,'').replace(/^www\./,'');
        const whoisMap = {
            com: "whois.verisign-grs.com",
            net: "whois.verisign-grs.com",
            org: "whois.pir.org",
            cn: "whois.cnnic.cn",
            top: "whois.nic.top",
            xyz: "whois.xyz",
            info: "whois.afilias.info",
            biz: "whois.biz"
        };
        const tld = cleanDomain.split('.').pop().toLowerCase();
        const whoisServer = whoisMap[tld] || "whois.verisign-grs.com";
        const whoisResult = await new Promise((resolve, reject) => {
            const sock = new net.Socket();
            let buf = "";
            sock.setTimeout(8000);
            sock.connect(43, whoisServer, () => {
                sock.write(cleanDomain + "\r\n");
            });
            sock.on('data', d => buf += d.toString());
            sock.on('close', () => resolve(buf));
            sock.on('timeout', () => { sock.destroy(); reject("查询超时"); });
            sock.on('error', e => { sock.destroy(); reject(e.message); });
        });
        res.json({success:true, domain:cleanDomain, raw:whoisResult});
    } catch(e){
        console.error("whois异常：",e);
        res.json({success:false, error:e.message});
    }
});

// =====================【新增：硬件上报接口】=====================
// 内存存储硬件上报记录，服务重启数据丢失
let hardwareRecordList = [];
// POST接收客户端硬件信息上报
app.post('/api/hardware/upload', async (req, res) => {
  try {
    const data = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    const uploadTime = new Date().toLocaleString();
    const record = {
      ...data,
      clientPublicIp: clientIp,
      uploadTime: uploadTime
    };
    hardwareRecordList.push(record);
    console.log("收到硬件上报数据：", record);
    res.json({success:true,msg:"上报成功"});
  } catch(err) {
    console.error("硬件上报报错：",err);
    res.json({success:false,msg:"上报失败:"+err.message})
  }
})
// GET读取全部硬件上报记录（后面前端页面用来展示设备列表）
app.get('/api/hardware/list', (req,res)=>{
  res.json({
    success:true,
    data: hardwareRecordList
  })
})
// ===============================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`服务启动，端口：${PORT}`);
})
