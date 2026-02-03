/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 3.1 (Pie Chart & Bug Fix Edition)
 */

const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');
const crypto = require('crypto');

// === 工具函数：SHA-256 哈希计算 ===
function hashPwd(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// 默认密码 "admin" 的哈希值
const DEFAULT_PWD_HASH = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";

// === 默认配置结构 ===
const DEFAULT_CONFIG = {
    passwordHash: DEFAULT_PWD_HASH,
    lbGroups: [
        { name: "🇭🇰 香港", regex: "HK|hong|🇭🇰" },
        { name: "🇯🇵 日本", regex: "JP|japan|🇯🇵" },
        { name: "🇨🇦 加拿大", regex: "CA|canada|🇨🇦" }
    ],
    appGroups: {
        "Sora&ChatGPT": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇹🇼 台湾", "🇸🇬 新加坡"], 
        "ABEMA": ["🇯🇵 日本"],
        "赛马娘PrettyDerby": ["🇯🇵 日本"],
        "PJSK-JP": ["🇯🇵 日本"],
        "Claude": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇬🇧 英国"]
    },
    dnsSettings: {
        enable: true,
        ipv6: false,
        'default-nameserver': ['223.5.5.5', '119.29.29.29'],
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'use-hosts': true,
        nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
        fallback: [
            'tls://8.8.4.4', 'tls://1.1.1.1',
            'https://doh-pure.onedns.net/dns-query', 'https://ada.openbld.net/dns-query'
        ],
        'fallback-filter': {
            geoip: true,
            ipcidr: ['240.0.0.0/4', '0.0.0.0/32'],
            domain: ['+.abema.tv', '+.abema.io', '+.ameba.jp', '+.hayabusa.io']
        }
    },
    includeUnmatched: true,
    healthCheckInterval: 120
};

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || 'Unknown';

    // =======================================================================
    // A. 统计逻辑 (异步记录)
    // =======================================================================
    if (subUrl && !action) {
        (async () => {
            try {
                // 简单处理 UA，提取核心部分避免 key 过长
                let simpleUA = ua.length > 50 ? ua.substring(0, 50) + '...' : ua;
                if(ua.includes('Clash')) simpleUA = 'Clash Core';
                if(ua.includes('Shadowrocket')) simpleUA = 'Shadowrocket';
                if(ua.includes('Mihomo')) simpleUA = 'Mihomo';
                
                const uaKey = `stat:${Buffer.from(simpleUA).toString('base64')}`;
                await kv.incr(uaKey);
                await kv.expire(uaKey, 86400);
            } catch (e) { console.error("Stats Error:", e); }
        })();
    }

    // =======================================================================
    // B. 管理后台 API (POST)
    // =======================================================================
    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword } = req.body;
        const savedConfig = await kv.get('global_config');
        const currentConfig = savedConfig || DEFAULT_CONFIG;
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        // 1. 登录验证
        if (action === 'login') {
            if (authHash === currentPwdHash) {
                const isDefault = currentPwdHash === DEFAULT_PWD_HASH;
                return res.json({ success: true, isDefaultPwd: isDefault });
            }
            return res.status(403).json({ success: false, msg: "密码错误" });
        }

        // 2. 忘记密码/系统重置 (不需要鉴权，因为是物理重置)
        if (action === 'resetSystem') {
            await kv.del('global_config');
            const keys = await kv.keys('stat:*');
            if (keys.length > 0) await kv.del(...keys);
            return res.json({ success: true, msg: "系统已重置，密码恢复为 admin" });
        }

        // --- 鉴权拦截 ---
        if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "会话失效或密码错误，请刷新页面" });

        // 3. 保存配置
        if (action === 'saveConfig') {
            const configToSave = { ...newConfig, passwordHash: currentPwdHash };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "✅ 全局配置已保存！" });
        }

        // 4. 重置配置 (修复 Bug: 确保这里逻辑正确)
        if (action === 'resetConfig') {
            // 只重置配置部分，保留密码
            const resetConfig = { ...DEFAULT_CONFIG, passwordHash: currentPwdHash };
            await kv.set('global_config', resetConfig);
            return res.json({ success: true, msg: "🔄 配置已重置为默认值 (密码保持不变)" });
        }

        // 5. 修改密码
        if (action === 'changePassword') {
            if (!newPassword) return res.status(400).json({ msg: "无效密码" });
            const configToSave = { ...currentConfig, passwordHash: newPassword };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "密码修改成功" });
        }
        
        // 6. 获取统计数据
        if (action === 'getStats') {
            try {
                const keys = await kv.keys('stat:*');
                const stats = [];
                if (keys.length > 0) {
                    const values = await kv.mget(...keys);
                    keys.forEach((key, index) => {
                        const uaStr = Buffer.from(key.replace('stat:', ''), 'base64').toString('utf-8');
                        stats.push({ ua: uaStr, count: parseInt(values[index] || 0) });
                    });
                }
                return res.json({ success: true, data: stats });
            } catch (e) { return res.json({ success: false, msg: e.message }); }
        }
    }

    // =======================================================================
    // C. 返回 Web 界面
    // =======================================================================
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = { 
            ...DEFAULT_CONFIG, 
            ...savedConfig,
            dnsSettings: { ...DEFAULT_CONFIG.dnsSettings, ...(savedConfig?.dnsSettings || {}) }
        };
        if (!currentConfig.passwordHash) currentConfig.passwordHash = DEFAULT_PWD_HASH;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // =======================================================================
    // D. 订阅生成逻辑
    // =======================================================================
    try {
        const savedConfig = await kv.get('global_config');
        const userConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        const intervalTime = userConfig.healthCheckInterval || 120;

        const isClash = /clash|mihomo|stash/i.test(ua);
        const response = await axios.get(subUrl, {
            headers: { 'User-Agent': isClash ? 'ClashMeta' : ua },
            responseType: 'text',
            timeout: 10000
        });

        if (!isClash) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
            return res.send(response.data);
        }

        let config = yaml.load(response.data);
        const allProxyNames = (config.proxies || []).map(p => p.name);

        if (userConfig.dnsSettings && userConfig.dnsSettings.enable) {
            config.dns = userConfig.dnsSettings;
        }

        const usedNodeNames = new Set();
        const lbGroupsOutput = [];

        userConfig.lbGroups.forEach(group => {
            const regex = new RegExp(group.regex, 'i');
            const matched = allProxyNames.filter(name => {
                const m = regex.test(name);
                if (m) usedNodeNames.add(name);
                return m;
            });

            lbGroupsOutput.push({
                name: `${group.name} 自动负载`, 
                type: "load-balance",
                proxies: matched.length > 0 ? matched : ["DIRECT"],
                url: "http://www.gstatic.com/generate_204",
                interval: parseInt(intervalTime),
                strategy: "round-robin"
            });
        });

        const unmatchedNodes = allProxyNames.filter(name => !usedNodeNames.has(name));

        const MY_GROUPS = [
            { 
                name: "ReiaNEXT", 
                type: "select", 
                proxies: ["♻️ 自动选择", ...lbGroupsOutput.map(g => g.name), "🚫 故障转移", ...(userConfig.includeUnmatched ? unmatchedNodes : [])] 
            }
        ];

        const targetApps = userConfig.appGroups || DEFAULT_CONFIG.appGroups;
        Object.keys(targetApps).forEach(appName => {
            const selectedRegions = targetApps[appName] || [];
            const validProxies = selectedRegions
                .map(regionName => `${regionName} 自动负载`)
                .filter(fullName => lbGroupsOutput.find(g => g.name === fullName));
            const finalProxies = validProxies.length > 0 ? validProxies : [];
            finalProxies.push("ReiaNEXT");
            MY_GROUPS.push({ name: appName, type: "select", proxies: finalProxies });
        });

        MY_GROUPS.push({ name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 });
        MY_GROUPS.push({ name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 });

        config['proxy-groups'] = [...MY_GROUPS, ...lbGroupsOutput];

        res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
        if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
        res.send(yaml.dump(config));

    } catch (err) {
        res.status(500).send(`Error: ${err.message}`);
    }
};

// =======================================================================
// E. 前端 HTML (含 Chart.js)
// =======================================================================
function renderAdminPage(config) {
    const dns = config.dnsSettings || DEFAULT_CONFIG.dnsSettings;
    const dnsDisplay = {
        ...dns,
        defaultNameserver: dns['default-nameserver'].join('\n'),
        nameserver: dns.nameserver.join('\n'),
        fallback: dns.fallback.join('\n'),
        ipcidr: dns['fallback-filter'].ipcidr.join('\n'),
        domain: dns['fallback-filter'].domain.join('\n')
    };

    return `
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia 后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); padding: 20px; min-height: 100vh; }
        .card { margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border:none;}
        [data-bs-theme="dark"] .card { box-shadow: 0 4px 12px rgba(0,0,0,0.4); background-color: #2b3035; }
        
        #login-overlay, #pwd-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(255, 255, 255, 0.4);
            backdrop-filter: blur(var(--blur-amt)); -webkit-backdrop-filter: blur(var(--blur-amt));
            z-index: 9998; display: flex; justify-content: center; align-items: center;
        }
        [data-bs-theme="dark"] #login-overlay, [data-bs-theme="dark"] #pwd-overlay { background: rgba(0, 0, 0, 0.6); }

        .login-box {
            background: var(--bs-body-bg); padding: 2.5rem; border-radius: 16px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2); width: 90%; max-width: 420px; text-align: center;
            border: 1px solid var(--bs-border-color);
        }
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        
        .theme-switcher { position: fixed; top: 20px; right: 20px; z-index: 9999; }
        .chart-container { position: relative; height: 300px; width: 100%; margin-bottom: 20px; }
        textarea.form-control { font-family: monospace; font-size: 0.85rem; }
    </style>
    <script>
        // 主题设置
        (() => {
            const getStoredTheme = () => localStorage.getItem('theme');
            const setStoredTheme = theme => localStorage.setItem('theme', theme);
            const getPreferredTheme = () => {
                const storedTheme = getStoredTheme();
                if (storedTheme) return storedTheme;
                return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
            }
            const setTheme = theme => {
                if (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    document.documentElement.setAttribute('data-bs-theme', 'dark');
                } else {
                    document.documentElement.setAttribute('data-bs-theme', theme);
                }
            }
            setTheme(getPreferredTheme());
            window.addEventListener('DOMContentLoaded', () => {
                document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
                    toggle.addEventListener('click', () => {
                        const theme = toggle.getAttribute('data-bs-theme-value');
                        setStoredTheme(theme); setTheme(theme);
                    });
                });
            });
        })();
    </script>
</head>
<body>

<div class="dropdown theme-switcher">
    <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown">主题</button>
    <ul class="dropdown-menu dropdown-menu-end shadow">
        <li><button class="dropdown-item" data-bs-theme-value="light">☀️ 浅色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="dark">🌙 深色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="auto">🖥️ 跟随系统</button></li>
    </ul>
</div>

<!-- 登录遮罩 -->
<div id="login-overlay">
    <div class="login-box">
        <h4 class="mb-4">🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg mb-3 text-center" placeholder="请输入密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div class="mt-3">
            <a href="#" class="text-danger small text-decoration-none" onclick="resetSystem()">忘记密码? 重置系统</a>
        </div>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<!-- 修改密码遮罩 -->
<div id="pwd-overlay" style="display:none; z-index:9999;">
    <div class="login-box">
        <h4 class="mb-3 text-warning">⚠️ 安全警告</h4>
        <p class="small text-muted">正在使用默认密码。请立即修改。</p>
        <input type="password" id="new_pwd" class="form-control mb-2" placeholder="新密码">
        <input type="password" id="confirm_pwd" class="form-control mb-3" placeholder="确认新密码">
        <button class="btn btn-warning w-100" onclick="changePassword()">确认修改</button>
        <div id="pwd-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<div class="container" id="main-app" style="max-width:900px">
    <div class="d-flex justify-content-between align-items-center mb-3 pt-2">
        <h3>🛠️ NextReia 后台</h3>
        <div>
            <button class="btn btn-outline-secondary btn-sm me-2" onclick="showChangePwd()">修改密码</button>
            <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">重置配置</button>
        </div>
    </div>

    <ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
        <li class="nav-item"><button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config-pane" type="button">⚙️ 配置管理</button></li>
        <li class="nav-item"><button class="nav-link" id="stats-tab" data-bs-toggle="tab" data-bs-target="#stats-pane" type="button" onclick="loadStats()">📊 使用统计</button></li>
    </ul>

    <div class="tab-content">
        <!-- 配置面板 -->
        <div class="tab-pane fade show active" id="config-pane">
            <!-- 1. 负载均衡 -->
            <div class="card">
                <div class="card-header text-primary bg-body-tertiary">1. 负载均衡组 (Regex)</div>
                <div class="card-body">
                    <div id="lb_area"></div>
                    <button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button>
                </div>
            </div>

            <!-- 2. 分流策略 -->
            <div class="card">
                <div class="card-header text-success bg-body-tertiary">2. 分流策略组配置</div>
                <div class="card-body" id="app_area"></div>
            </div>

            <!-- 3. DNS -->
            <div class="card">
                <div class="card-header text-info bg-body-tertiary">3. DNS 覆写设置</div>
                <div class="card-body">
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="dns_enable" ${dnsDisplay.enable ? 'checked' : ''}>
                        <label class="form-check-label fw-bold">启用 DNS 覆写</label>
                    </div>
                    <div class="row g-3">
                         <div class="col-md-6">
                            <label class="form-label small">IPv6</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" id="dns_ipv6" ${dnsDisplay.ipv6 ? 'checked' : ''}>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <label class="form-label small">Enhanced Mode</label>
                            <select id="dns_enhanced" class="form-select form-select-sm">
                                <option value="fake-ip" ${dnsDisplay['enhanced-mode'] === 'fake-ip' ? 'selected' : ''}>fake-ip</option>
                                <option value="redir-host" ${dnsDisplay['enhanced-mode'] === 'redir-host' ? 'selected' : ''}>redir-host</option>
                            </select>
                        </div>
                        <div class="col-md-6"><label class="form-label small">Fake-IP Range</label><input type="text" id="dns_fakeip" class="form-control form-control-sm" value="${dnsDisplay['fake-ip-range']}"></div>
                        <div class="col-md-6"><label class="form-label small">Use Hosts</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_hosts" ${dnsDisplay['use-hosts'] ? 'checked' : ''}></div></div>
                        <div class="col-12"><label class="form-label small">Default Nameserver</label><textarea id="dns_default_ns" class="form-control" rows="2">${dnsDisplay.defaultNameserver}</textarea></div>
                        <div class="col-12"><label class="form-label small">Nameserver</label><textarea id="dns_ns" class="form-control" rows="3">${dnsDisplay.nameserver}</textarea></div>
                        <div class="col-12"><label class="form-label small">Fallback</label><textarea id="dns_fallback" class="form-control" rows="3">${dnsDisplay.fallback}</textarea></div>
                        <div class="col-12"><hr><h6>Fallback Filter</h6></div>
                        <div class="col-md-4"><label class="form-label small">GeoIP</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_geoip" ${dnsDisplay['fallback-filter'].geoip ? 'checked' : ''}></div></div>
                        <div class="col-md-8"><label class="form-label small">IP CIDR</label><textarea id="dns_ipcidr" class="form-control" rows="2">${dnsDisplay.ipcidr}</textarea></div>
                        <div class="col-12"><label class="form-label small">Domain</label><textarea id="dns_domain" class="form-control" rows="3">${dnsDisplay.domain}</textarea></div>
                    </div>
                </div>
            </div>

            <!-- 4. 高级设置 -->
            <div class="card">
                <div class="card-header text-secondary bg-body-tertiary">4. 高级设置</div>
                <div class="card-body">
                    <div class="mb-3 row align-items-center">
                        <label class="col-sm-4 col-form-label">健康检查间隔 (秒)</label>
                        <div class="col-sm-4"><input type="number" id="interval" class="form-control" value="${config.healthCheckInterval || 120}" min="60"></div>
                    </div>
                    <div class="form-check form-switch">
                        <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                        <label class="form-check-label">未匹配节点放入 ReiaNEXT</label>
                    </div>
                </div>
            </div>
            <button class="btn btn-success w-100 p-3 shadow mb-5" onclick="save()">保存全局配置</button>
        </div>

        <!-- 统计面板 -->
        <div class="tab-pane fade" id="stats-pane">
            <div class="card">
                <div class="card-header bg-body-tertiary d-flex justify-content-between align-items-center">
                    <span>📊 24小时请求统计</span>
                    <button class="btn btn-sm btn-outline-secondary" onclick="loadStats()">刷新</button>
                </div>
                <div class="card-body">
                    <!-- 饼图容器 -->
                    <div class="chart-container d-flex justify-content-center">
                        <canvas id="statsChart"></canvas>
                    </div>
                    
                    <div class="table-responsive mt-3">
                        <table class="table table-striped table-hover mb-0 stats-table">
                            <thead class="table-light">
                                <tr><th onclick="sortStats('ua')">客户端 (UA) ↕</th><th onclick="sortStats('count')" class="text-end">次数 ↕</th></tr>
                            </thead>
                            <tbody id="stats_tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
    let currentConfig = ${JSON.stringify(config)};
    let authTokenHash = sessionStorage.getItem('authHash') || ""; // 使用 SessionStorage 防止刷新丢失
    const defaultApps = ["Sora&ChatGPT", "ABEMA", "赛马娘PrettyDerby", "PJSK-JP", "Claude"];
    let statsData = [];
    let sortAsc = false;
    let myChart = null;

    function hash(str) { return CryptoJS.SHA256(str).toString(CryptoJS.enc.Hex); }

    // 检查是否有缓存的 Hash，尝试自动登录（界面上不显示遮罩）
    if(authTokenHash) {
        document.getElementById('login-overlay').style.display = 'none';
        document.getElementById('main-app').classList.add('active');
        renderUI();
    }

    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value;
        const msg = document.getElementById('login-msg');
        if(!pwd) return msg.innerText = "不能为空";
        
        const pwdHash = hash(pwd);
        try {
            const resp = await fetch('/?action=login', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ authHash: pwdHash })
            });
            const res = await resp.json();
            if (res.success) {
                authTokenHash = pwdHash;
                sessionStorage.setItem('authHash', pwdHash); // 存入会话存储
                document.getElementById('login-overlay').style.display = 'none';
                if (res.isDefaultPwd) { document.getElementById('pwd-overlay').style.display = 'flex'; }
                else { document.getElementById('main-app').classList.add('active'); renderUI(); }
            } else { msg.innerText = "密码错误"; }
        } catch (e) { msg.innerText = "网络错误"; }
    }
    document.getElementById('login_pwd').addEventListener('keypress', e => e.key === 'Enter' && doLogin());

    async function changePassword() {
        const p1 = document.getElementById('new_pwd').value;
        const p2 = document.getElementById('confirm_pwd').value;
        if (!p1 || p1.length < 5) return alert("密码太短");
        if (p1 !== p2) return alert("两次输入不一致");
        try {
            const resp = await fetch('/?action=changePassword', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ authHash: authTokenHash, newPassword: hash(p1) })
            });
            const res = await resp.json();
            if (res.success) { alert("修改成功，请重新登录"); sessionStorage.clear(); location.reload(); }
            else { alert(res.msg); }
        } catch (e) { alert("请求失败"); }
    }
    function showChangePwd() { document.getElementById('pwd-overlay').style.display = 'flex'; }

    async function resetSystem() {
        if(!confirm("警告：将清除所有数据恢复初始状态！")) return;
        await fetch('/?action=resetSystem', { method: 'POST' });
        alert("系统已重置"); location.reload();
    }

    // === 渲染与保存 ===
    function renderUI() {
        document.getElementById('lb_area').innerHTML = '';
        currentConfig.lbGroups.forEach(val => addLB(val));
        renderAppGroups();
    }
    function addLB(val = {name:'', regex:''}) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 lb-item';
        div.innerHTML = \`<input type="text" class="form-control lb-n" value="\${val.name}" oninput="updateAppChoices()"><input type="text" class="form-control lb-r" value="\${val.regex}"><button class="btn btn-danger" onclick="removeLB(this)">×</button>\`;
        document.getElementById('lb_area').appendChild(div);
    }
    function removeLB(btn) { btn.parentElement.remove(); updateAppChoices(); }
    function renderAppGroups() {
        const container = document.getElementById('app_area'); container.innerHTML = '';
        const apps = Object.keys(currentConfig.appGroups).length > 0 ? Object.keys(currentConfig.appGroups) : defaultApps;
        apps.forEach(app => {
            const row = document.createElement('div'); row.className = 'app-row p-2 border-bottom'; row.dataset.app = app;
            const selected = currentConfig.appGroups[app] || [];
            let html = \`<div class="fw-bold mb-1">\${app}</div><div class="checkbox-grid d-flex flex-wrap gap-2">\`;
            getLBNames().forEach(lb => {
                const chk = selected.includes(lb) ? 'checked' : '';
                html += \`<div class="form-check form-check-inline m-0"><input class="form-check-input" type="checkbox" value="\${lb}" \${chk}><label class="form-check-label small">\${lb}</label></div>\`;
            });
            html += \`</div>\`; row.innerHTML = html; container.appendChild(row);
        });
    }
    function getLBNames() {
        const names = []; document.querySelectorAll('.lb-n').forEach(i => { if(i.value) names.push(i.value); });
        return names.length > 0 ? names : currentConfig.lbGroups.map(g => g.name);
    }
    function updateAppChoices() { /* 简化: 可以在这里添加实时保存选中状态的逻辑，当前仅刷新列表 */ renderAppGroups(); }

    async function save() {
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({ name: el.querySelector('.lb-n').value, regex: el.querySelector('.lb-r').value })).filter(i=>i.name);
        const appGroups = {}; document.querySelectorAll('.app-row').forEach(row => { appGroups[row.dataset.app] = Array.from(row.querySelectorAll('input:checked')).map(i=>i.value); });
        const split = (id) => document.getElementById(id).value.split('\\n').map(s=>s.trim()).filter(s=>s);
        const dnsSettings = {
            enable: document.getElementById('dns_enable').checked,
            ipv6: document.getElementById('dns_ipv6').checked,
            'default-nameserver': split('dns_default_ns'),
            'enhanced-mode': document.getElementById('dns_enhanced').value,
            'fake-ip-range': document.getElementById('dns_fakeip').value,
            'use-hosts': document.getElementById('dns_hosts').checked,
            nameserver: split('dns_ns'),
            fallback: split('dns_fallback'),
            'fallback-filter': { geoip: document.getElementById('dns_geoip').checked, ipcidr: split('dns_ipcidr'), domain: split('dns_domain') }
        };
        const newConfig = { lbGroups, appGroups, dnsSettings, includeUnmatched: document.getElementById('unmatched').checked, healthCheckInterval: document.getElementById('interval').value };

        try {
            const resp = await fetch('/?action=saveConfig', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ authHash: authTokenHash, newConfig })
            });
            if(resp.status === 403) { alert("Session失效"); sessionStorage.clear(); location.reload(); return; }
            const res = await resp.json(); alert(res.msg); currentConfig = newConfig;
        } catch(e) { alert("保存失败"); }
    }

    // 修复后的重置配置逻辑
    async function resetConfig() {
        if(!confirm("确定重置配置？(密码不变)")) return;
        try {
            const resp = await fetch('/?action=resetConfig', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ authHash: authTokenHash })
            });
            if(resp.status === 403) { alert("请重新登录"); sessionStorage.clear(); location.reload(); return; }
            const res = await resp.json(); alert(res.msg); location.reload();
        } catch(e) { alert("重置失败"); }
    }

    // === 统计与图表 ===
    async function loadStats() {
        const tbody = document.getElementById('stats_tbody'); tbody.innerHTML = '<tr><td colspan="2">加载中...</td></tr>';
        try {
            const resp = await fetch('/?action=getStats', {
                method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash })
            });
            const res = await resp.json();
            if (res.success) { statsData = res.data; renderStatsTable(); renderChart(); }
            else { tbody.innerHTML = '<tr><td colspan="2">加载失败</td></tr>'; }
        } catch (e) { tbody.innerHTML = '<tr><td colspan="2">错误</td></tr>'; }
    }
    function renderStatsTable() {
        const tbody = document.getElementById('stats_tbody'); tbody.innerHTML = '';
        if (statsData.length === 0) return tbody.innerHTML = '<tr><td colspan="2">无数据</td></tr>';
        statsData.forEach(item => {
            const tr = document.createElement('tr');
            tr.innerHTML = \`<td class="small text-break">\${item.ua}</td><td class="text-end">\${item.count}</td>\`;
            tbody.appendChild(tr);
        });
    }
    function sortStats(key) {
        sortAsc = !sortAsc;
        statsData.sort((a, b) => key === 'count' ? (sortAsc ? a.count - b.count : b.count - a.count) : (sortAsc ? a.ua.localeCompare(b.ua) : b.ua.localeCompare(a.ua)));
        renderStatsTable();
    }

    // 渲染饼图
    function renderChart() {
        const ctx = document.getElementById('statsChart').getContext('2d');
        if (myChart) myChart.destroy();
        
        // 数据处理：只取前5，其他的合并为 Others
        let chartData = [...statsData].sort((a,b) => b.count - a.count);
        let labels = [], data = [], bgColors = [];
        const colors = ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#C9CBCF'];
        
        if (chartData.length > 5) {
            const top5 = chartData.slice(0, 5);
            const others = chartData.slice(5).reduce((acc, curr) => acc + curr.count, 0);
            top5.forEach(i => { labels.push(i.ua.substring(0,15)); data.push(i.count); });
            labels.push('Others'); data.push(others);
        } else {
            chartData.forEach(i => { labels.push(i.ua.substring(0,20)); data.push(i.count); });
        }
        
        myChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{ data: data, backgroundColor: colors }]
            },
            options: { maintainAspectRatio: false, plugins: { legend: { position: 'right' } } }
        });
    }
</script>
</body>
</html>`;
}