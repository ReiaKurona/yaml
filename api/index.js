/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 7.0 (Smart Import, Auto-Correction, Context-Aware)
 * 
 * Update Notes:
 * - Rewrote batchImport() to handle Markdown lists, comments, and typos.
 * - Added logic to auto-replace rule target with current group name when not in Global mode.
 */

const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');
const crypto = require('crypto');

// === 工具函数 ===
function hashPwd(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

const DEFAULT_PWD_HASH = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
const DEFAULT_APP_NAMES = ["Sora&ChatGPT", "ABEMA", "赛马娘PrettyDerby", "PJSK-JP", "Claude"];

const ALL_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", 
    "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP", "SRC-IP-CIDR", 
    "SRC-PORT", "DST-PORT", "PROCESS-NAME", "PROCESS-PATH", "UID", "NETWORK", "DSCP", 
    "RULE-SET", "AND", "OR", "NOT", "SUB-RULE"
];

const BUILT_IN_POLICIES = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"];

const DEFAULT_CONFIG = {
    passwordHash: DEFAULT_PWD_HASH,
    enableOverwrite: true,
    uiSettings: { backgroundImage: "" },
    lbGroups: [
        { name: "🇭🇰 香港", regex: "HK|hong|🇭🇰|IEPL" },
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
    customAppGroups: [],
    customGlobalRules: [],
    groupOrder: [...DEFAULT_APP_NAMES],
    dnsSettings: {
        enable: true,
        ipv6: false,
        'default-nameserver': ['223.5.5.5', '119.29.29.29'],
        'enhanced-mode': 'fake-ip',
        'fake-ip-range': '198.18.0.1/16',
        'use-hosts': true,
        nameserver: ['https://doh.pub/dns-query', 'https://dns.alidns.com/dns-query'],
        fallback: ['tls://8.8.4.4', 'tls://1.1.1.1', 'https://doh-pure.onedns.net/dns-query'],
        'fallback-filter': { geoip: true, ipcidr: ['240.0.0.0/4', '0.0.0.0/32'], domain: ['+.abema.tv', '+.abema.io', '+.ameba.jp'] }
    },
    includeUnmatched: true,
    healthCheckInterval: 120
};

// 全局错误捕获
module.exports = async (req, res) => {
    try {
        await handleRequest(req, res);
    } catch (err) {
        console.error("Runtime Error:", err);
        res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send(`<div style="padding:20px;font-family:sans-serif;"><h3>🔴 服务端错误</h3><p>请检查 KV 数据库连接或依赖安装。</p><pre style="background:#eee;padding:10px;">${err.stack}</pre></div>`);
    }
};

async function handleRequest(req, res) {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || 'Unknown';
    const clientIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : (req.socket.remoteAddress || 'Unknown');

    // A. 统计逻辑
    if (subUrl && !action) {
        (async () => {
            try {
                const uaKey = `stat:ua:${Buffer.from(ua).toString('base64')}`;
                await kv.incr(uaKey);
                await kv.expire(uaKey, 86400);
                
                const ipKey = `stat:ip:${clientIp}`;
                await kv.incr(ipKey);
                await kv.expire(ipKey, 86400);

                await kv.incr('stat:total');
            } catch (e) { console.error("Stats Error (Non-blocking):", e.message); }
        })();
    }

    // B. 管理 API
    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword, previewUrl, type: statsType } = req.body;
        const savedConfig = await kv.get('global_config');
        const currentConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        // Login
        if (action === 'login') {
            if (authHash === currentPwdHash) return res.json({ success: true, isDefaultPwd: currentPwdHash === DEFAULT_PWD_HASH });
            return res.status(403).json({ success: false, msg: "密码错误" });
        }
        // Factory Reset
        if (action === 'factoryReset') {
            await kv.flushall();
            return res.json({ success: true, msg: "♻️ 已恢复出厂设置" });
        }
        // Preview
        if (action === 'preview') {
            if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "会话失效" });
            try {
                const previewRes = await generateConfig(previewUrl, "ClashMeta", currentConfig, true);
                return res.json({ success: true, data: previewRes });
            } catch (e) { return res.json({ success: false, msg: "生成预览失败: " + e.message }); }
        }
        
        // Auth check
        if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "会话失效" });

        if (action === 'saveConfig') {
            const configToSave = { ...newConfig, passwordHash: currentPwdHash };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "✅ 设置已保存" });
        }
        if (action === 'resetConfig') {
            const resetConfig = { ...DEFAULT_CONFIG, passwordHash: currentPwdHash, uiSettings: currentConfig.uiSettings };
            await kv.set('global_config', resetConfig);
            return res.json({ success: true, msg: "🔄 配置项已重置" });
        }
        if (action === 'clearStats') {
            const keys = await kv.keys('stat:*');
            if (keys.length > 0) await kv.del(...keys);
            return res.json({ success: true, msg: "🧹 统计已清空" });
        }
        if (action === 'changePassword') {
            if (!newPassword) return res.status(400).json({ msg: "无效密码" });
            const configToSave = { ...currentConfig, passwordHash: newPassword };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "密码修改成功" });
        }
        if (action === 'getStats') {
            try {
                const reqType = statsType || 'ua';
                const matchPattern = reqType === 'ip' ? 'stat:ip:*' : 'stat:ua:*';
                const keys = await kv.keys(matchPattern);
                const total = await kv.get('stat:total') || 0;
                
                const stats = [];
                if (keys.length > 0) {
                    const values = await kv.mget(...keys);
                    keys.forEach((key, index) => {
                        let label = key.replace(reqType === 'ip' ? 'stat:ip:' : 'stat:ua:', '');
                        if (reqType === 'ua') {
                            try { label = Buffer.from(label, 'base64').toString('utf-8'); } catch(e){ label = "Invalid Key"; }
                        }
                        stats.push({ label: label, count: parseInt(values[index] || 0) });
                    });
                }
                return res.json({ success: true, data: stats, total: total, globalOverwrite: currentConfig.enableOverwrite });
            } catch (e) { return res.json({ success: false, msg: e.message }); }
        }
    }

    // C. 返回 Web 界面
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = { 
            ...DEFAULT_CONFIG, 
            ...savedConfig,
            dnsSettings: { ...DEFAULT_CONFIG.dnsSettings, ...(savedConfig?.dnsSettings || {}) },
            uiSettings: { ...DEFAULT_CONFIG.uiSettings, ...(savedConfig?.uiSettings || {}) }
        };
        if (!currentConfig.customAppGroups) currentConfig.customAppGroups = [];
        if (!currentConfig.customGlobalRules) currentConfig.customGlobalRules = [];
        if (!currentConfig.groupOrder) currentConfig.groupOrder = [...DEFAULT_APP_NAMES];

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // D. 订阅生成
    const savedConfig = await kv.get('global_config');
    const userConfig = { ...DEFAULT_CONFIG, ...savedConfig };
    
    const isClash = /clash|mihomo|stash/i.test(ua);
    if (!isClash || !userConfig.enableOverwrite) {
        const response = await axios.get(subUrl, { headers: { 'User-Agent': ua }, responseType: 'text', timeout: 10000 });
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
        return res.send(response.data);
    }

    const yamlResult = await generateConfig(subUrl, ua, userConfig, false);
    
    const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
    if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
    
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.send(yamlResult);
}

// === 辅助生成函数 ===
async function generateConfig(subUrl, ua, userConfig, forceOverwrite) {
    if (!userConfig.customAppGroups) userConfig.customAppGroups = [];
    if (!userConfig.customGlobalRules) userConfig.customGlobalRules = [];
    if (!userConfig.groupOrder) userConfig.groupOrder = [...DEFAULT_APP_NAMES];
    const intervalTime = userConfig.healthCheckInterval || 120;

    const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
    let config = yaml.load(response.data);
    const allProxyNames = (config.proxies || []).map(p => p.name);

    if (userConfig.dnsSettings && userConfig.dnsSettings.enable) {
        config.dns = userConfig.dnsSettings;
    }

    const usedNodeNames = new Set();
    const lbGroupsOutput = [];
    userConfig.lbGroups.forEach(group => {
        const regex = new RegExp(group.regex, 'i');
        const matched = allProxyNames.filter(name => regex.test(name));
        if (matched.length > 0) matched.forEach(n => usedNodeNames.add(n));
        lbGroupsOutput.push({
            name: `${group.name} 自动负载`, type: "load-balance", proxies: matched.length > 0 ? matched : ["DIRECT"],
            url: "http://www.gstatic.com/generate_204", interval: parseInt(intervalTime), strategy: "round-robin"
        });
    });

    const unmatchedNodes = allProxyNames.filter(name => !usedNodeNames.has(name));
    const MY_GROUPS = [{ name: "ReiaNEXT", type: "select", proxies: ["♻️ 自动选择", ...lbGroupsOutput.map(g => g.name), "🚫 故障转移", ...(userConfig.includeUnmatched ? unmatchedNodes : [])] }];

    userConfig.groupOrder.forEach(groupName => {
        let targetProxies = [];
        if (DEFAULT_APP_NAMES.includes(groupName)) {
            const selectedRegions = userConfig.appGroups[groupName] || [];
            const validProxies = selectedRegions.map(r => `${r} 自动负载`).filter(f => lbGroupsOutput.find(g => g.name === f));
            targetProxies = validProxies.length > 0 ? validProxies : [];
        } else {
            const customGroup = userConfig.customAppGroups.find(g => g.name === groupName);
            if (customGroup) {
                const selectedRegions = customGroup.targetLBs || [];
                const validProxies = selectedRegions.map(r => `${r} 自动负载`).filter(f => lbGroupsOutput.find(g => g.name === f));
                targetProxies = validProxies.length > 0 ? validProxies : [];
            }
        }
        targetProxies.push("ReiaNEXT");
        MY_GROUPS.push({ name: groupName, type: "select", proxies: targetProxies });
    });

    MY_GROUPS.push({ name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 });
    MY_GROUPS.push({ name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 });

    config['proxy-groups'] = [...MY_GROUPS, ...lbGroupsOutput];

    const injectedRules = [];
    userConfig.customGlobalRules.forEach(r => injectedRules.push(`${r.type},${r.value},${r.target}${r.noResolve ? ',no-resolve' : ''}`));
    userConfig.customAppGroups.forEach(cg => {
        if (cg.rules) cg.rules.forEach(r => injectedRules.push(`${r.type},${r.value},${cg.name}${r.noResolve ? ',no-resolve' : ''}`));
    });
    config.rules = [...injectedRules, ...(config.rules || [])];

    return yaml.dump(config);
}

function renderAdminPage(config) {
    const dns = config.dnsSettings || DEFAULT_CONFIG.dnsSettings;
    const ui = config.uiSettings || { backgroundImage: "", ipApiSource: "ipapi.co", customIpApiUrl: "" };
    
    const dnsDisplay = {
        ...dns,
        defaultNameserver: dns['default-nameserver'].join('\n'),
        nameserver: dns.nameserver.join('\n'),
        fallback: dns.fallback.join('\n'),
        ipcidr: dns['fallback-filter'].ipcidr.join('\n'),
        domain: dns['fallback-filter'].domain.join('\n')
    };

    const customBgCss = ui.backgroundImage ? 
        `body { background: linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), url('${ui.backgroundImage}') no-repeat center center fixed; background-size: cover; }
         .card { background-color: rgba(255, 255, 255, 0.9); }
         [data-bs-theme="dark"] .card { background-color: rgba(33, 37, 41, 0.95); }` 
        : '';

    return `
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia Pro V7.0</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-yaml.min.js"></script>
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); transition: background 0.3s; padding: 20px; min-height: 100vh; padding-top: 60px; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.08); transition: background-color 0.3s; }
        [data-bs-theme="dark"] .card { box-shadow: 0 4px 12px rgba(0,0,0,0.4); background-color: #2b3035; }
        ${customBgCss}
        .help-icon { cursor: pointer; color: #0d6efd; margin-left: 5px; font-size: 0.9em; opacity: 0.8; }
        .theme-switcher { position: fixed; top: 15px; right: 20px; z-index: 10000; }
        #login-overlay, #pwd-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.4); backdrop-filter: blur(var(--blur-amt)); -webkit-backdrop-filter: blur(var(--blur-amt)); z-index: 9998; display: flex; justify-content: center; align-items: center; }
        [data-bs-theme="dark"] #login-overlay, [data-bs-theme="dark"] #pwd-overlay { background: rgba(0, 0, 0, 0.6); }
        .login-box { background: var(--bs-body-bg); padding: 2.5rem; border-radius: 16px; box-shadow: 0 15px 35px rgba(0,0,0,0.2); width: 90%; max-width: 420px; text-align: center; border: 1px solid var(--bs-border-color); position: relative; }
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        .chart-container { position: relative; height: 300px; width: 100%; margin-bottom: 20px; }
        textarea.form-control { font-family: monospace; font-size: 0.85rem; }
        .list-group-item { cursor: default; display: flex; align-items: center; justify-content: space-between; gap: 10px; }
        .sort-handle { cursor: grab; color: #adb5bd; padding: 5px; font-size: 1.2rem; touch-action: none; }
        .sort-handle:active { cursor: grabbing; }
        .badge-proxy { background-color: #0d6efd; }
        .badge-browser { background-color: #6c757d; }
        /* Fix Checkbox Grid overflow */
        .checkbox-grid { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; width: 100%; }
        .checkbox-grid .form-check { margin: 0; }
        #modal-app-choices { max-height: 200px; overflow-y: auto; padding: 10px; border: 1px solid var(--bs-border-color); border-radius: 5px; }
        .rule-type-select { max-width: 140px; }
        [data-bs-theme="dark"] .btn-outline-dark { color: #f8f9fa; border-color: #f8f9fa; }
        [data-bs-theme="dark"] .btn-outline-dark:hover { background-color: #f8f9fa; color: #000; }
        #preview_container { background-color: #1e1e1e; border-radius: 6px; padding: 15px; border: 1px solid #444; max-height: 600px; overflow: auto; }
        [data-bs-theme="light"] #preview_container { background-color: #f8f9fa; border: 1px solid #dee2e6; }
        code { font-family: Consolas, Monaco, monospace; font-size: 0.85rem; }
    </style>
    <script>
        (() => {
            const getStoredTheme = () => localStorage.getItem('theme');
            const setStoredTheme = theme => localStorage.setItem('theme', theme);
            const getPreferredTheme = () => { const storedTheme = getStoredTheme(); if (storedTheme) return storedTheme; return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }
            const setTheme = theme => { if (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches) { document.documentElement.setAttribute('data-bs-theme', 'dark'); } else { document.documentElement.setAttribute('data-bs-theme', theme); } }
            setTheme(getPreferredTheme());
            window.addEventListener('DOMContentLoaded', () => {
                document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => { toggle.addEventListener('click', () => { const theme = toggle.getAttribute('data-bs-theme-value'); setStoredTheme(theme); setTheme(theme); }); });
                const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
                tooltipTriggerList.map(function (tooltipTriggerEl) { return new bootstrap.Tooltip(tooltipTriggerEl) });
            });
        })();
    </script>
</head>
<body>

<div class="dropdown theme-switcher">
    <button class="btn btn-outline-secondary dropdown-toggle shadow-sm" type="button" data-bs-toggle="dropdown">🎨 主题</button>
    <ul class="dropdown-menu dropdown-menu-end shadow">
        <li><button class="dropdown-item" data-bs-theme-value="light">☀️ 浅色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="dark">🌙 深色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="auto">🖥️ 跟随系统</button></li>
    </ul>
</div>

<div id="login-overlay">
    <div class="login-box">
        <h4 class="mb-4">🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg mb-3 text-center" placeholder="请输入密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div class="mt-3"><a href="#" class="text-danger small text-decoration-none" onclick="factoryReset()">忘记密码? 恢复出厂设置</a></div>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<!-- Rule Modal with Tabs -->
<div class="modal fade" id="ruleModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="ruleModalTitle">编辑规则</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <ul class="nav nav-tabs mb-3">
                    <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#edit-visual">可视化编辑</button></li>
                    <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#edit-batch">智能批量导入</button></li>
                </ul>
                <div class="tab-content">
                    <div class="tab-pane fade show active" id="edit-visual">
                        <div id="rule-list-container"></div>
                        <button class="btn btn-sm btn-outline-success mt-2" onclick="addRuleRow()">+ 新增规则</button>
                    </div>
                    <div class="tab-pane fade" id="edit-batch">
                        <div class="alert alert-info small p-2">
                            <strong>✨ 智能导入模式：</strong><br>
                            1. 支持复制粘贴整段规则（含注释 # 或 //）。<br>
                            2. 自动识别 <code>- DOMAIN...</code> 列表格式。<br>
                            3. 自动忽略空行和无效行。<br>
                            4. <strong>如果是分流策略组模式</strong>，目标(Proxy/DIRECT等)会被自动修正为当前组名。<br>
                            5. 自动纠正常见拼写错误 (如 DOMAINSUFFIX)。
                        </div>
                        <textarea id="batch-rule-input" class="form-control font-monospace" rows="12" placeholder="# 示例：
- DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD, niconico, Proxy, no-resolve
# 注释行会被忽略"></textarea>
                        <button class="btn btn-sm btn-primary mt-2" onclick="batchImport()">⚡ 智能识别并导入</button>
                    </div>
                </div>
                <div id="modal-target-section" class="mt-3"><hr><h6>目标负载均衡组</h6><div id="modal-app-choices" class="checkbox-grid"></div></div>
            </div>
            <div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="saveRulesFromModal()">保存规则</button></div>
        </div>
    </div>
</div>

<div id="pwd-overlay" style="display:none; z-index:9999;">
    <div style="position:absolute; width:100%; height:100%;" onclick="closePwdModal()"></div>
    <div class="login-box">
        <div id="pwd-close-btn" style="position:absolute;top:10px;right:15px;cursor:pointer;font-size:1.5rem;" onclick="closePwdModal()">&times;</div>
        <h4 class="mb-3 text-warning">⚠️ 修改密码</h4>
        <input type="password" id="new_pwd" class="form-control mb-2" placeholder="新密码">
        <input type="password" id="confirm_pwd" class="form-control mb-3" placeholder="确认新密码">
        <button class="btn btn-warning w-100" onclick="changePassword()">确认修改</button>
    </div>
</div>

<div class="container" id="main-app" style="max-width:950px">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h3 class="fw-bold">🛠️ NextReia Pro V7.0</h3>
        <div><button class="btn btn-outline-secondary btn-sm me-2" onclick="showChangePwd(false)">修改密码</button><button class="btn btn-danger btn-sm" onclick="doLogout()">退出</button></div>
    </div>

    <ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
        <li class="nav-item"><button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config-pane">⚙️ 配置</button></li>
        <li class="nav-item"><button class="nav-link" id="ui-tab" data-bs-toggle="tab" data-bs-target="#ui-pane">🎨 界面</button></li>
        <li class="nav-item"><button class="nav-link" id="preview-tab" data-bs-toggle="tab" data-bs-target="#preview-pane">👁️ 预览</button></li>
        <li class="nav-item"><button class="nav-link" id="stats-tab" data-bs-toggle="tab" data-bs-target="#stats-pane" onclick="loadStats()">📊 统计</button></li>
    </ul>

    <div class="tab-content">
        <div class="tab-pane fade show active" id="config-pane">
            <div class="card border-primary border-2">
                <div class="card-body d-flex justify-content-between align-items-center">
                    <div><h5 class="mb-0 text-primary fw-bold">🔥 全局覆写开关</h5><small class="text-muted">关闭时 Clash 直接获取原订阅</small></div>
                    <div class="form-check form-switch form-switch-lg"><input class="form-check-input" type="checkbox" role="switch" id="enable_overwrite" style="transform: scale(1.5);" ${config.enableOverwrite ? 'checked' : ''}></div>
                </div>
            </div>
            <div class="card"><div class="card-header text-primary bg-body-tertiary">1. 负载均衡组 (Regex)</div><div class="card-body"><div id="lb_area"></div><button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button></div></div>
            <div class="card"><div class="card-header text-warning bg-body-tertiary d-flex justify-content-between"><span>2. 分流策略组</span><button class="btn btn-sm btn-success" onclick="addNewCustomGroup()">+ 新增</button></div><div class="card-body"><ul class="list-group" id="sortable-groups"></ul></div></div>
            <div class="card"><div class="card-header text-success bg-body-tertiary">3. 分流策略组目标配置</div><div class="card-body" id="app_area"></div></div>
            <div class="card">
                <div class="card-header text-info bg-body-tertiary d-flex align-items-center">4. DNS 覆写设置</div>
                <div class="card-body">
                    <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="dns_enable" ${dnsDisplay.enable ? 'checked' : ''}><label class="form-check-label fw-bold">启用</label></div>
                    <div class="row g-3">
                        <div class="col-md-6"><label class="form-label small">IPv6</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_ipv6" ${dnsDisplay.ipv6 ? 'checked' : ''}></div></div>
                        <div class="col-md-6"><label class="form-label small">Enhanced Mode</label><select id="dns_enhanced" class="form-select form-select-sm"><option value="fake-ip" ${dnsDisplay['enhanced-mode'] === 'fake-ip' ? 'selected' : ''}>fake-ip</option><option value="redir-host" ${dnsDisplay['enhanced-mode'] === 'redir-host' ? 'selected' : ''}>redir-host</option></select></div>
                        <div class="col-md-6"><label class="form-label small">Fake-IP Range</label><input type="text" id="dns_fakeip" class="form-control form-control-sm" value="${dnsDisplay['fake-ip-range']}"></div><div class="col-md-6"><label class="form-label small">Use Hosts</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_hosts" ${dnsDisplay['use-hosts'] ? 'checked' : ''}></div></div>
                        <div class="col-12"><label class="form-label small">Default Nameserver</label><textarea id="dns_default_ns" class="form-control" rows="2">${dnsDisplay.defaultNameserver}</textarea></div>
                        <div class="col-12"><label class="form-label small">Nameserver</label><textarea id="dns_ns" class="form-control" rows="3">${dnsDisplay.nameserver}</textarea></div>
                        <div class="col-12"><label class="form-label small">Fallback</label><textarea id="dns_fallback" class="form-control" rows="3">${dnsDisplay.fallback}</textarea></div>
                        <div class="col-12"><hr><h6>Fallback Filter</h6></div><div class="col-md-4"><label class="form-label small">GeoIP</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_geoip" ${dnsDisplay['fallback-filter'].geoip ? 'checked' : ''}></div></div><div class="col-md-8"><label class="form-label small">IP CIDR</label><textarea id="dns_ipcidr" class="form-control" rows="2">${dnsDisplay.ipcidr}</textarea></div><div class="col-12"><label class="form-label small">Domain</label><textarea id="dns_domain" class="form-control" rows="3">${dnsDisplay.domain}</textarea></div>
                    </div>
                </div>
            </div>
            <div class="card"><div class="card-header text-secondary bg-body-tertiary">5. 高级设置</div><div class="card-body"><button class="btn btn-outline-dark w-100 mb-3" onclick="openGlobalRuleEditor()">🌐 编辑全局/预置规则</button><div class="mb-3 row align-items-center"><label class="col-sm-4 col-form-label">健康检查间隔 (秒)</label><div class="col-sm-4"><input type="number" id="interval" class="form-control" value="${config.healthCheckInterval || 120}" min="60"></div></div><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}><label class="form-check-label">未匹配节点放入 ReiaNEXT</label></div></div></div>
            <div class="d-flex gap-2 mb-5"><button class="btn btn-outline-secondary flex-grow-1 p-3" onclick="resetConfig()">⚠️ 重置配置</button><button class="btn btn-success flex-grow-1 p-3 shadow" onclick="save()">保存所有设置</button></div>
        </div>

        <div class="tab-pane fade" id="ui-pane">
            <div class="card"><div class="card-header">🎨 个性化</div><div class="card-body">
                <div class="mb-3"><label class="form-label">背景图片 URL</label><input type="text" id="bg_image" class="form-control" placeholder="https://..." value="${ui.backgroundImage}"></div>
                <hr>
                <h6 class="mb-3">IP 数据源设置 (用于统计页面)</h6>
                <div class="mb-3"><label class="form-label">数据源选择</label>
                    <select id="ip_api_source" class="form-select" onchange="toggleCustomApi()">
                        <option value="ipapi.co" ${ui.ipApiSource==='ipapi.co'?'selected':''}>ipapi.co (HTTPS, 推荐)</option>
                        <option value="ip-api.com" ${ui.ipApiSource==='ip-api.com'?'selected':''}>ip-api.com (HTTP, 中文, 需浏览器允许)</option>
                        <option value="ip.sb" ${ui.ipApiSource==='ip.sb'?'selected':''}>ip.sb (HTTPS, 极简)</option>
                        <option value="custom" ${ui.ipApiSource==='custom'?'selected':''}>自定义 API</option>
                    </select>
                </div>
                <div class="mb-3" id="custom_api_div" style="display:none"><label class="form-label">自定义 API URL (使用 {ip} 占位)</label><input type="text" id="custom_ip_api" class="form-control" placeholder="https://api.example.com/{ip}" value="${ui.customIpApiUrl}"></div>
                <button class="btn btn-primary" onclick="save()">保存界面设置</button>
            </div></div>
            <div class="card"><div class="card-header bg-info-subtle">💾 备份与还原</div><div class="card-body"><div class="d-flex gap-2"><button class="btn btn-outline-primary" onclick="exportSettings()">📤 导出</button><button class="btn btn-outline-success" onclick="document.getElementById('file_import').click()">📥 导入</button><input type="file" id="file_import" accept=".json" style="display:none" onchange="importSettings(this)"></div></div></div>
            <div class="card border-danger"><div class="card-header text-danger">🧨 危险区域</div><div class="card-body"><button class="btn btn-danger w-100" onclick="factoryReset()">恢复出厂设置</button></div></div>
        </div>

        <div class="tab-pane fade" id="preview-pane">
            <div class="card"><div class="card-header">👁️ 预览实验室</div><div class="card-body"><div class="mb-3"><div class="input-group"><input type="text" id="preview_sub_url" class="form-control" placeholder="粘贴订阅链接..."><button class="btn btn-info" onclick="generatePreview()">生成预览</button></div></div><div id="preview_container"><pre><code id="preview_code" class="language-yaml"># 点击生成后显示...</code></pre></div></div></div>
        </div>

        <div class="tab-pane fade" id="stats-pane">
            <div class="card"><div class="card-header bg-body-tertiary d-flex justify-content-between align-items-center"><span>📊 统计 <span id="total-req" class="badge bg-secondary ms-2"></span></span><div><div class="btn-group me-2" role="group"><button type="button" class="btn btn-sm btn-outline-primary active" id="btn-ua" onclick="switchStats('ua')">UA视图</button><button type="button" class="btn btn-sm btn-outline-primary" id="btn-ip" onclick="switchStats('ip')">IP视图</button></div><button class="btn btn-sm btn-outline-danger me-2" onclick="clearStats()">清空</button><button class="btn btn-sm btn-outline-secondary" onclick="loadStats()">刷新</button></div></div><div class="card-body"><div class="chart-container d-flex justify-content-center"><canvas id="statsChart"></canvas></div><div id="stats_tables"></div></div></div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

<script>
    let config = ${JSON.stringify(config)};
    let authTokenHash = sessionStorage.getItem('authHash') || "";
    const DEFAULT_APP_NAMES = ${JSON.stringify(DEFAULT_APP_NAMES)};
    const ALL_RULE_TYPES = ${JSON.stringify(ALL_RULE_TYPES)};
    const BUILT_IN_POLICIES = ${JSON.stringify(BUILT_IN_POLICIES)};
    let editingMode = null; let editingGroupName = null; let myChart = null;
    let currentStatsType = 'ua'; let statsSortKey = 'count'; let statsSortAsc = false;
    let currentStatsData = []; let currentIsOverwrite = true;

    if(authTokenHash) { document.getElementById('login-overlay').style.display = 'none'; document.getElementById('main-app').classList.add('active'); renderUI(); }
    function hash(str) { return CryptoJS.SHA256(str).toString(CryptoJS.enc.Hex); }

    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value; const pwdHash = hash(pwd);
        try {
            const res = await (await fetch('/?action=login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: pwdHash }) })).json();
            if (res.success) { authTokenHash = pwdHash; sessionStorage.setItem('authHash', pwdHash); document.getElementById('login-overlay').style.display = 'none'; if (res.isDefaultPwd) showChangePwd(true); else { document.getElementById('main-app').classList.add('active'); renderUI(); } } else { alert("密码错误"); }
        } catch (e) { alert("网络错误"); }
    }
    document.getElementById('login_pwd').addEventListener('keypress', e => e.key === 'Enter' && doLogin());
    function doLogout() { sessionStorage.removeItem('authHash'); location.reload(); }
    async function factoryReset() { if(!confirm("⚠️ 严重警告：彻底清除所有数据？")) return; await fetch('/?action=factoryReset', { method: 'POST' }); alert("已重置"); location.reload(); }
    async function resetConfig() { if(!confirm("仅重置配置？")) return; await fetch('/?action=resetConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) }); alert("配置已重置"); location.reload(); }

    function renderUI() {
        document.getElementById('lb_area').innerHTML = ''; config.lbGroups.forEach(val => addLB(val));
        renderSortableGroups(); renderAppGroups();
        toggleCustomApi();
    }
    function toggleCustomApi() {
        const val = document.getElementById('ip_api_source').value;
        document.getElementById('custom_api_div').style.display = val === 'custom' ? 'block' : 'none';
    }
    
    function renderSortableGroups() {
        const list = document.getElementById('sortable-groups'); list.innerHTML = '';
        config.groupOrder.forEach(name => {
            const isDefault = DEFAULT_APP_NAMES.includes(name);
            const li = document.createElement('li'); li.className = 'list-group-item'; li.dataset.name = name;
            let btns = isDefault ? \`<span class="badge bg-secondary ms-2">默认</span><button class="btn btn-sm btn-outline-secondary ms-2" disabled>规则</button><button class="btn btn-sm btn-outline-danger ms-1" disabled>删</button>\` : \`<span class="badge bg-info text-dark ms-2">自定义</span><button class="btn btn-sm btn-outline-primary ms-2" onclick="openRuleEditor('group', '\${name}')">规则</button><button class="btn btn-sm btn-outline-danger ms-1" onclick="deleteCustomGroup('\${name}')">删</button>\`;
            li.innerHTML = \`<div class="d-flex align-items-center flex-grow-1"><span class="sort-handle me-2">☰</span><input type="text" class="form-control form-control-sm group-name-input" value="\${name}" \${isDefault ? 'disabled' : ''} onchange="updateGroupName('\${name}', this.value)">\${btns}</div>\`;
            list.appendChild(li);
        });
        new Sortable(list, { handle: '.sort-handle', animation: 150, ghostClass: 'ghost-class', onEnd: function (evt) { config.groupOrder = Array.from(list.children).map(li => li.dataset.name); renderAppGroups(); } });
    }
    function addNewCustomGroup() { const name = prompt("新组名称:", "MyGroup"); if (name && !config.groupOrder.includes(name)) { config.groupOrder.splice(1, 0, name); config.customAppGroups.push({ name: name, rules: [], targetLBs: [] }); renderSortableGroups(); renderAppGroups(); } }
    function deleteCustomGroup(name) { if (!confirm(\`确认删除 \${name} ?\`)) return; config.groupOrder = config.groupOrder.filter(n => n !== name); config.customAppGroups = config.customAppGroups.filter(g => g.name !== name); renderSortableGroups(); renderAppGroups(); }
    function updateGroupName(oldName, newName) { if (oldName === newName || DEFAULT_APP_NAMES.includes(oldName)) return; const idx = config.groupOrder.indexOf(oldName); if (idx !== -1) config.groupOrder[idx] = newName; const grp = config.customAppGroups.find(g => g.name === oldName); if (grp) grp.name = newName; renderSortableGroups(); renderAppGroups(); }
    function validateRule(type, value) { if (!value) return false; if (type.startsWith('IP-CIDR') || type.startsWith('SRC-IP-CIDR')) return /^(\\d{1,3}\\.){3}\\d{1,3}(\\/\\d{1,2})?$/.test(value) || /^[0-9a-fA-F:]+(\\/\\d{1,3})?$/.test(value); if (type.startsWith('DOMAIN')) return /^[a-zA-Z0-9-.*]+$/.test(value); return true; }

    const ruleModal = new bootstrap.Modal(document.getElementById('ruleModal'));
    function openRuleEditor(mode, groupName) {
        editingMode = mode; editingGroupName = groupName;
        document.getElementById('rule-list-container').innerHTML = ''; document.getElementById('batch-rule-input').value = '';
        const targetSection = document.getElementById('modal-target-section');
        let rules = [];
        if (mode === 'global') { document.getElementById('ruleModalTitle').innerText = "全局/预置规则"; rules = config.customGlobalRules || []; targetSection.style.display = 'none'; }
        else {
            document.getElementById('ruleModalTitle').innerText = groupName; const grp = config.customAppGroups.find(g => g.name === groupName); rules = grp ? (grp.rules || []) : []; targetSection.style.display = 'block';
            const appChoiceContainer = document.getElementById('modal-app-choices'); appChoiceContainer.innerHTML = '';
            const targets = grp ? (grp.targetLBs || []) : [];
            getLBNames().forEach(lb => {
                const chk = targets.includes(lb) ? 'checked' : '';
                appChoiceContainer.innerHTML += \`<div class="form-check form-check-inline border p-1 rounded"><input class="form-check-input modal-target-chk" type="checkbox" value="\${lb}" \${chk}><label class="form-check-label small">\${lb}</label></div>\`;
            });
        }
        rules.forEach(r => addRuleRow(r.type, r.value, r.target, r.noResolve));
        ruleModal.show();
    }
    function openGlobalRuleEditor() { openRuleEditor('global'); }
    function addRuleRow(type = 'DOMAIN-SUFFIX', val = '', target = '', noResolve = false) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 rule-row';
        let typeOpts = ALL_RULE_TYPES.map(t => \`<option value="\${t}" \${type===t?'selected':''}>\${t}</option>\`).join('');
        let targetInput = '';
        if (editingMode === 'global') { let policyOpts = BUILT_IN_POLICIES.map(p => \`<option value="\${p}" \${target===p?'selected':''}>\${p}</option>\`).join(''); targetInput = \`<select class="form-select form-select-sm rule-target" style="max-width:120px">\${policyOpts}</select>\`; }
        let nrCheck = \`<div class="input-group-text"><input class="form-check-input mt-0 rule-no-resolve" type="checkbox" \${noResolve?'checked':''} aria-label="no-resolve"> <span class="small ms-1">no-res</span></div>\`;
        div.innerHTML = \`<select class="form-select form-select-sm rule-type rule-type-select">\${typeOpts}</select><input type="text" class="form-control form-control-sm rule-value" placeholder="值" value="\${val}">\${targetInput}\${nrCheck}<button class="btn btn-outline-danger btn-sm" onclick="this.parentElement.remove()">×</button>\`;
        document.getElementById('rule-list-container').appendChild(div);
    }
    
    // === 智能批量导入逻辑 V7.0 ===
    function batchImport() {
        const text = document.getElementById('batch-rule-input').value;
        const lines = text.split('\\n');
        let count = 0;

        lines.forEach(line => {
            // 1. 预处理：去除注释 (# 或 // 后面的内容) 和首尾空白
            let cleanLine = line.split('#')[0].split('//')[0].trim();
            // 2. 去除列表符号 (如 "- ", "* ")
            cleanLine = cleanLine.replace(/^[-*]\\s+/, '');

            if (!cleanLine) return;

            // 3. 智能分割：支持逗号或空格分隔
            let parts = cleanLine.includes(',') 
                ? cleanLine.split(',').map(s => s.trim()) 
                : cleanLine.split(/\\s+/).map(s => s.trim());

            if (parts.length >= 2) {
                let type = parts[0].toUpperCase();
                // 容错处理
                if (type === 'DOMAINSUFFIX') type = 'DOMAIN-SUFFIX';
                if (type === 'IPCIDR') type = 'IP-CIDR';

                const val = parts[1];
                let target = '';
                let noRes = cleanLine.toLowerCase().includes('no-resolve');

                // 4. 目标处理：分流组模式下强制覆盖为当前组名
                if (editingMode === 'global') {
                    if (parts.length > 2 && !parts[2].toLowerCase().includes('no-resolve')) {
                        target = parts[2];
                    }
                } else {
                    target = editingGroupName; // 强制设为当前编辑的组名
                }

                if (ALL_RULE_TYPES.includes(type)) {
                    addRuleRow(type, val, target, noRes);
                    count++;
                }
            }
        });
        alert(\`智能识别并导入 \${count} 条规则\`);
        new bootstrap.Tab(document.querySelector('button[data-bs-target="#edit-visual"]')).show();
    }

    function saveRulesFromModal() {
        const rows = document.querySelectorAll('.rule-row'); const newRules = []; let hasError = false;
        rows.forEach(row => {
            const t = row.querySelector('.rule-type').value; const v = row.querySelector('.rule-value').value;
            if(!validateRule(t, v)) { row.querySelector('.rule-value').classList.add('is-invalid'); hasError = true; } 
            else {
                row.querySelector('.rule-value').classList.remove('is-invalid');
                const r = { type: t, value: v, noResolve: row.querySelector('.rule-no-resolve').checked };
                if (editingMode === 'global') r.target = row.querySelector('.rule-target').value;
                newRules.push(r);
            }
        });
        if(hasError) return alert("规则校验失败");
        if (editingMode === 'global') { config.customGlobalRules = newRules; } 
        else {
            const targets = Array.from(document.querySelectorAll('.modal-target-chk:checked')).map(i => i.value);
            const grp = config.customAppGroups.find(g => g.name === editingGroupName);
            if (grp) { grp.rules = newRules; grp.targetLBs = targets; } 
            else { config.customAppGroups.push({ name: editingGroupName, rules: newRules, targetLBs: targets }); }
        }
        ruleModal.hide(); if(editingMode !== 'global') renderAppGroups(); 
    }

    function renderAppGroups() {
        const container = document.getElementById('app_area'); container.innerHTML = '';
        config.groupOrder.forEach(appName => {
            const isDefault = DEFAULT_APP_NAMES.includes(appName);
            const row = document.createElement('div'); row.className = 'app-row p-2 border-bottom'; row.dataset.app = appName;
            let selected = [];
            if (isDefault) selected = config.appGroups[appName] || [];
            else { const grp = config.customAppGroups.find(g => g.name === appName); selected = grp ? (grp.targetLBs || []) : []; }
            let html = \`<div class="d-flex justify-content-between"><span class="fw-bold mb-1">\${appName} \${!isDefault ? '<small class="text-info">(自定义)</small>' : ''}</span></div><div class="checkbox-grid">\`;
            getLBNames().forEach(lb => {
                const chk = selected.includes(lb) ? 'checked' : '';
                html += \`<div class="form-check form-check-inline m-0"><input class="form-check-input" type="checkbox" value="\${lb}" \${chk}><label class="form-check-label small">\${lb}</label></div>\`;
            });
            html += \`</div>\`; row.innerHTML = html; container.appendChild(row);
        });
    }
    function getLBNames() { const names = []; document.querySelectorAll('.lb-n').forEach(i => { if(i.value) names.push(i.value); }); return names.length > 0 ? names : config.lbGroups.map(g => g.name); }
    function addLB(val = {name:'', regex:''}) { const div = document.createElement('div'); div.className = 'input-group mb-2 lb-item'; div.innerHTML = \`<input type="text" class="form-control lb-n" value="\${val.name}"><input type="text" class="form-control lb-r" value="\${val.regex}"><button class="btn btn-danger" onclick="this.parentElement.remove(); renderAppGroups();">×</button>\`; document.getElementById('lb_area').appendChild(div); }

    function exportSettings() {
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(config));
        const a = document.createElement('a'); a.setAttribute("href", dataStr); a.setAttribute("download", "nextreia_backup.json"); document.body.appendChild(a); a.click(); a.remove();
    }
    function importSettings(input) {
        const file = input.files[0]; if(!file) return;
        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                const imported = JSON.parse(e.target.result);
                if(!imported.lbGroups) throw new Error("Format Error");
                const newConfig = { ...config, ...imported, passwordHash: config.passwordHash };
                await fetch('/?action=saveConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newConfig }) });
                alert("导入成功"); location.reload();
            } catch(err) { alert("导入失败"); }
        }; reader.readAsText(file);
    }

    async function save() {
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({ name: el.querySelector('.lb-n').value, regex: el.querySelector('.lb-r').value })).filter(i=>i.name);
        const appGroups = {}; const updatedCustomGroups = [...config.customAppGroups];
        document.querySelectorAll('.app-row').forEach(row => {
            const appName = row.dataset.app; const selected = Array.from(row.querySelectorAll('input:checked')).map(i=>i.value);
            if (DEFAULT_APP_NAMES.includes(appName)) appGroups[appName] = selected;
            else { const grp = updatedCustomGroups.find(g => g.name === appName); if (grp) grp.targetLBs = selected; }
        });
        const split = (id) => document.getElementById(id).value.split('\\n').map(s=>s.trim()).filter(s=>s);
        const dnsSettings = {
            enable: document.getElementById('dns_enable').checked, ipv6: document.getElementById('dns_ipv6').checked,
            'default-nameserver': split('dns_default_ns'), 'enhanced-mode': document.getElementById('dns_enhanced').value,
            'fake-ip-range': document.getElementById('dns_fakeip').value, 'use-hosts': document.getElementById('dns_hosts').checked,
            nameserver: split('dns_ns'), fallback: split('dns_fallback'),
            'fallback-filter': { geoip: document.getElementById('dns_geoip').checked, ipcidr: split('dns_ipcidr'), domain: split('dns_domain') }
        };
        const uiSettings = { 
            backgroundImage: document.getElementById('bg_image').value,
            ipApiSource: document.getElementById('ip_api_source').value,
            customIpApiUrl: document.getElementById('custom_ip_api').value
        };
        const newConfig = { 
            ...config, lbGroups, appGroups, customAppGroups: updatedCustomGroups, groupOrder: config.groupOrder, dnsSettings, customGlobalRules: config.customGlobalRules,
            includeUnmatched: document.getElementById('unmatched').checked, healthCheckInterval: document.getElementById('interval').value,
            enableOverwrite: document.getElementById('enable_overwrite').checked, uiSettings
        };
        try {
            const resp = await fetch('/?action=saveConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newConfig }) });
            if(resp.status === 403) { alert("Session失效"); location.reload(); return; }
            alert((await resp.json()).msg);
            if(newConfig.uiSettings.backgroundImage !== config.uiSettings.backgroundImage) location.reload();
            config = newConfig;
        } catch(e) { alert("保存失败"); }
    }

    async function generatePreview() {
        const url = document.getElementById('preview_sub_url').value; if(!url) return alert("请输入URL");
        document.getElementById('preview_code').textContent = "生成中...";
        try {
            const res = await (await fetch('/?action=preview', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, previewUrl: url }) })).json();
            if(res.success) { document.getElementById('preview_code').textContent = res.data; Prism.highlightElement(document.getElementById('preview_code')); } 
            else document.getElementById('preview_code').textContent = "错误: " + res.msg;
        } catch(e) { document.getElementById('preview_code').textContent = "Error"; }
    }

    function switchStats(type) {
        currentStatsType = type;
        document.getElementById('btn-ua').classList.toggle('active', type==='ua');
        document.getElementById('btn-ip').classList.toggle('active', type==='ip');
        loadStats();
    }

    async function loadStats() {
        const res = await (await fetch('/?action=getStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, type: currentStatsType }) })).json();
        if (res.success) { 
            document.getElementById('total-req').innerText = 'Total: ' + res.total;
            renderStats(res.data, res.globalOverwrite); 
        }
    }
    
    // --- IP Enrichment ---
    async function fetchIpDetails(ip) {
        let apiUrl = '';
        const source = config.uiSettings.ipApiSource;
        if(source === 'ipapi.co') apiUrl = \`https://ipapi.co/\${ip}/json/\`;
        else if(source === 'ip-api.com') apiUrl = \`http://ip-api.com/json/\${ip}?lang=zh-CN\`;
        else if(source === 'ip.sb') apiUrl = \`https://api.ip.sb/geoip/\${ip}\`;
        else if(source === 'custom') apiUrl = config.uiSettings.customIpApiUrl.replace('{ip}', ip);
        
        try {
            const res = await fetch(apiUrl);
            if(!res.ok) throw new Error('Fetch failed');
            return await res.json();
        } catch(e) { return null; }
    }

    function renderStats(data, isOverwriteEnabled) {
        const container = document.getElementById('stats_tables'); container.innerHTML = '';
        if (!data || data.length === 0) {
            container.innerHTML = '<div class="text-center text-muted py-5">暂无数据，请尝试连接一次订阅链接</div>';
            if(myChart) myChart.destroy();
            return;
        }

        if(currentStatsType === 'ua') {
            const proxyClients = data.filter(i => /Clash|Mihomo|Stash|Shadowrocket|Surfboard|v2ray/i.test(i.label));
            const browserClients = data.filter(i => !/Clash|Mihomo|Stash|Shadowrocket|Surfboard|v2ray/i.test(i.label));
            if(proxyClients.length > 0) container.innerHTML += createStatsTable("🚀 代理客户端", proxyClients, true, isOverwriteEnabled);
            if(browserClients.length > 0) container.innerHTML += createStatsTable("🌐 浏览器 / 其他", browserClients, false);
        } else {
            // IP View with Enrichment
            container.innerHTML += createStatsTable("📍 来源 IP", data, false);
            // Trigger delayed fetch for IPs
            setTimeout(() => {
                data.forEach((item, index) => {
                    if(index > 20) return; // Limit fetches to top 20 to avoid rate limit
                    const rowId = \`ip-row-\${index}\`;
                    const ip = item.label;
                    fetchIpDetails(ip).then(details => {
                        if(!details) return;
                        let loc = details.country || details.country_name || '';
                        if(details.city) loc += ' ' + details.city;
                        let asn = details.org || details.isp || details.asn_organization || '';
                        if(details.asn) asn = \`\${details.asn} \${asn}\`;
                        
                        const locCell = document.getElementById(\`\${rowId}-loc\`);
                        const asnCell = document.getElementById(\`\${rowId}-asn\`);
                        if(locCell && loc) locCell.innerText = loc;
                        if(asnCell && asn) asnCell.innerText = asn;
                    });
                });
            }, 500);
        }
        
        if (myChart) myChart.destroy();
        const ctx = document.getElementById('statsChart').getContext('2d');
        const labels = data.slice(0,10).map(i=>i.label.substring(0,20));
        const chartData = data.slice(0,10).map(i=>i.count);
        myChart = new Chart(ctx, { type: 'doughnut', data: { labels, datasets: [{ data: chartData, backgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0', '#9966FF'] }] } });
    }

    function createStatsTable(title, items, showOverwrite, isOverwriteEnabled) {
        if (items.length === 0) return '';
        items.sort((a, b) => statsSortKey === 'count' ? (statsSortAsc ? a.count - b.count : b.count - a.count) : (statsSortAsc ? a.label.localeCompare(b.label) : b.label.localeCompare(a.label)));
        
        const isIpView = currentStatsType === 'ip';
        const extraHeaders = isIpView ? '<th>归属地</th><th>详情 (ASN/ISP)</th>' : (showOverwrite?'<th>覆写状态</th>':'');
        
        let html = \`<h6 class="mt-4">\${title}</h6><div class="table-responsive"><table class="table table-sm table-striped"><thead><tr><th onclick="toggleSort('ua')" style="cursor:pointer">\${currentStatsType.toUpperCase()} ↕</th>\${extraHeaders}<th onclick="toggleSort('count')" class="text-end" style="cursor:pointer">次数 ↕</th></tr></thead><tbody>\`;
        
        items.forEach((i, idx) => {
            let middle = '';
            if (isIpView) {
                middle = \`<td id="ip-row-\${idx}-loc" class="text-muted small">Loading...</td><td id="ip-row-\${idx}-asn" class="text-muted small">-</td>\`;
            } else if (showOverwrite) {
                middle = \`<td>\${(isOverwriteEnabled) ? '<span class="badge bg-success">✅ 是</span>' : '<span class="badge bg-secondary">❌ 否</span>'}</td>\`;
            }
            html += \`<tr><td class="small text-break">\${i.label}</td>\${middle}<td class="text-end">\${i.count}</td></tr>\`;
        });
        html += '</tbody></table></div>'; return html;
    }

    function toggleSort(key) {
        if (statsSortKey === key) statsSortAsc = !statsSortAsc;
        else { statsSortKey = key; statsSortAsc = false; }
        renderStats(currentStatsData, currentIsOverwrite);
    }

    async function clearStats() { if(!confirm("清空统计？")) return; await fetch('/?action=clearStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) }); loadStats(); }
    function showChangePwd(forced) { const m = document.getElementById('pwd-overlay'); m.style.display = 'flex'; document.getElementById('pwd-close-btn').style.display = forced ? 'none' : 'block'; m.onclick = forced ? null : ((e) => { if(e.target===m) closePwdModal() }); document.getElementById('pwd-warning').style.display = forced ? 'block' : 'none'; }
    function closePwdModal() { document.getElementById('pwd-overlay').style.display = 'none'; }
    async function changePassword() { const p1 = document.getElementById('new_pwd').value, p2 = document.getElementById('confirm_pwd').value; if(p1.length<5 || p1!==p2) return alert("无效"); const res = await (await fetch('/?action=changePassword', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newPassword: hash(p1) }) })).json(); if(res.success) { alert("成功"); location.reload(); } else { alert(res.msg); } }
</script>
</body>
</html>`;
}