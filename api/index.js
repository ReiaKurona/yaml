/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 3.0 (Security & Stats & DNS Edition)
 * 
 * Features:
 * 1. Password Security: SHA-256 Hashing, Force Change Default, System Reset.
 * 2. Analytics: 24h UA Stats with TTL, Sortable Table.
 * 3. Configuration: Load Balance (Regex), Split Routing, DNS Overwrite.
 * 4. UI: Dark Mode, Responsive, Tabs.
 */

const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');
const crypto = require('crypto');

// === 工具函数：SHA-256 哈希计算 ===
function hashPwd(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// 默认密码 "admin" 的哈希值 (SHA-256)
// 如果你想改默认密码，可以算出新密码的hash替换这里
const DEFAULT_PWD_HASH = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";

// === 默认配置结构 ===
const DEFAULT_CONFIG = {
    // 密码哈希 (初始为 admin)
    passwordHash: DEFAULT_PWD_HASH,
    
    // 负载均衡组
    lbGroups: [
        { name: "🇭🇰 香港", regex: "HK|hong|🇭🇰" },
        { name: "🇯🇵 日本", regex: "JP|japan|🇯🇵" },
        { name: "🇨🇦 加拿大", regex: "CA|canada|🇨🇦" }
    ],
    // 应用分流
    appGroups: {
        "Sora&ChatGPT": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇹🇼 台湾", "🇸🇬 新加坡"], 
        "ABEMA": ["🇯🇵 日本"],
        "赛马娘PrettyDerby": ["🇯🇵 日本"],
        "PJSK-JP": ["🇯🇵 日本"],
        "Claude": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇬🇧 英国"]
    },
    // DNS 覆写配置 (Mihomo 规范)
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
    // 高级设置
    includeUnmatched: true,
    healthCheckInterval: 120
};

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || 'Unknown';

    // =======================================================================
    // A. 统计逻辑 (异步记录，仅在下发订阅时触发)
    // =======================================================================
    // 只有当存在 subUrl 且非 API 操作时，才计入统计
    if (subUrl && !action) {
        (async () => {
            try {
                // 使用 Base64 编码 UA 作为 Key 的一部分，避免特殊字符问题
                const uaKey = `stat:${Buffer.from(ua).toString('base64')}`;
                // 原子操作：增加计数并重置过期时间为 24小时 (86400秒)
                // 这样既实现了统计，又自动清理了超过24小时未活跃的 UA
                await kv.incr(uaKey);
                await kv.expire(uaKey, 86400);
            } catch (e) {
                console.error("Stats Error:", e);
            }
        })(); // 立即执行但不 await，避免阻塞主线程响应
    }

    // =======================================================================
    // B. 管理后台 API (POST)
    // =======================================================================
    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword } = req.body; // 注意：前端传过来的是哈希后的密码

        // 读取当前配置以获取真实密码哈希
        const savedConfig = await kv.get('global_config');
        const currentConfig = savedConfig || DEFAULT_CONFIG;
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        // --- 1. 登录验证 ---
        if (action === 'login') {
            // 前端传来的 authHash 应该是 SHA256(输入密码)
            if (authHash === currentPwdHash) {
                // 检查是否需要修改默认密码
                const isDefault = currentPwdHash === DEFAULT_PWD_HASH;
                return res.json({ success: true, isDefaultPwd: isDefault });
            }
            return res.status(403).json({ success: false, msg: "密码错误" });
        }

        // --- 2. 系统重置 (无需原密码，相当于物理重置按钮) ---
        // 为了防止恶意调用，这里做一个简单的逻辑：清除 KV
        if (action === 'resetSystem') {
            await kv.del('global_config');
            // 清除所有统计数据 (可选)
            const keys = await kv.keys('stat:*');
            if (keys.length > 0) await kv.del(...keys);
            
            return res.json({ success: true, msg: "系统已重置，密码恢复为 admin" });
        }

        // --- 以下操作需要鉴权 ---
        if (authHash !== currentPwdHash) return res.status(403).json({ msg: "会话失效或密码错误" });

        // --- 3. 保存配置 ---
        if (action === 'saveConfig') {
            // 保持密码不变，更新其他配置
            const configToSave = { ...newConfig, passwordHash: currentPwdHash };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "✅ 全局配置已保存！" });
        }

        // --- 4. 修改密码 ---
        if (action === 'changePassword') {
            if (!newPassword) return res.status(400).json({ msg: "新密码无效" });
            // 更新配置中的密码哈希
            const configToSave = { ...currentConfig, passwordHash: newPassword }; // newPassword 已经是前端哈希过的
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "密码修改成功，请重新登录" });
        }
        
        // --- 5. 获取统计数据 ---
        if (action === 'getStats') {
            try {
                const keys = await kv.keys('stat:*');
                const stats = [];
                if (keys.length > 0) {
                    // 批量获取值
                    const values = await kv.mget(...keys);
                    keys.forEach((key, index) => {
                        // 还原 UA
                        const uaStr = Buffer.from(key.replace('stat:', ''), 'base64').toString('utf-8');
                        stats.push({ ua: uaStr, count: parseInt(values[index] || 0) });
                    });
                }
                return res.json({ success: true, data: stats });
            } catch (e) {
                return res.json({ success: false, msg: e.message });
            }
        }
    }

    // =======================================================================
    // C. 返回 Web 管理界面 (无参数访问)
    // =======================================================================
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        // 深度合并配置，确保新字段存在
        const currentConfig = { 
            ...DEFAULT_CONFIG, 
            ...savedConfig,
            dnsSettings: { ...DEFAULT_CONFIG.dnsSettings, ...(savedConfig?.dnsSettings || {}) }
        };
        // 确保 passwordHash 存在
        if (!currentConfig.passwordHash) currentConfig.passwordHash = DEFAULT_PWD_HASH;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // =======================================================================
    // D. 订阅转换核心逻辑
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

        // 非 Clash 客户端，原样转发
        if (!isClash) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
            return res.send(response.data);
        }

        // Clash 解析
        let config = yaml.load(response.data);
        const allProxyNames = (config.proxies || []).map(p => p.name);

        // 1. DNS 覆写 (仅针对 Clash/Mihomo)
        if (userConfig.dnsSettings && userConfig.dnsSettings.enable) {
            config.dns = userConfig.dnsSettings;
        }

        // 2. 负载均衡组生成
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

        // 3. 策略组组装
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
// E. 前端 HTML 模板 (包含 JS 逻辑)
// =======================================================================
function renderAdminPage(config) {
    // 预处理 DNS 数据方便前端显示 (将数组转为换行字符串)
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
    <title>NextReia 高级管理后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); transition: background-color 0.3s; padding: 20px; min-height: 100vh; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        [data-bs-theme="dark"] .card { box-shadow: 0 4px 12px rgba(0,0,0,0.4); background-color: #2b3035; }
        .card-header { font-weight: 600; }
        
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
        .nav-tabs .nav-link { cursor: pointer; }
        textarea.form-control { font-size: 0.85rem; font-family: monospace; }
        
        /* 统计表格样式 */
        .stats-table th { cursor: pointer; user-select: none; }
        .stats-table th:hover { background-color: var(--bs-tertiary-bg); }
    </style>
    <script>
        // 主题初始化
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

<!-- 主题切换 -->
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

<!-- 强制修改密码遮罩 (默认隐藏) -->
<div id="pwd-overlay" style="display:none; z-index:9999;">
    <div class="login-box">
        <h4 class="mb-3 text-warning">⚠️ 安全警告</h4>
        <p class="small text-muted">检测到您正在使用默认密码 "admin"。<br>为了安全，请立即修改密码。</p>
        <input type="password" id="new_pwd" class="form-control mb-2" placeholder="新密码">
        <input type="password" id="confirm_pwd" class="form-control mb-3" placeholder="确认新密码">
        <button class="btn btn-warning w-100" onclick="changePassword()">确认修改</button>
        <div id="pwd-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<!-- 主界面 -->
<div class="container" id="main-app" style="max-width:900px">
    <div class="d-flex justify-content-between align-items-center mb-3 pt-2">
        <h3>🛠️ NextReia 管理后台</h3>
        <div>
            <button class="btn btn-outline-secondary btn-sm me-2" onclick="showChangePwd()">修改密码</button>
            <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">重置配置</button>
        </div>
    </div>

    <!-- 导航标签 -->
    <ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
        <li class="nav-item" role="presentation">
            <button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config-pane" type="button">⚙️ 配置管理</button>
        </li>
        <li class="nav-item" role="presentation">
            <button class="nav-link" id="stats-tab" data-bs-toggle="tab" data-bs-target="#stats-pane" type="button" onclick="loadStats()">📊 使用统计</button>
        </li>
    </ul>

    <div class="tab-content" id="myTabContent">
        <!-- 配置面板 -->
        <div class="tab-pane fade show active" id="config-pane" role="tabpanel">
            <!-- 1. 负载均衡组 -->
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

            <!-- 3. DNS 设置 -->
            <div class="card">
                <div class="card-header text-info bg-body-tertiary">3. DNS 覆写设置 (Clash/Mihomo)</div>
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
                        <div class="col-md-6">
                            <label class="form-label small">Fake-IP Range</label>
                            <input type="text" id="dns_fakeip" class="form-control form-control-sm" value="${dnsDisplay['fake-ip-range']}">
                        </div>
                         <div class="col-md-6">
                            <label class="form-label small">Use Hosts</label>
                            <div class="form-check form-switch">
                                <input class="form-check-input" type="checkbox" 
