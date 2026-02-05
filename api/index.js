/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 5.0 (Full Rules Support, Preview Lab, Enhanced UI)
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

// Mihomo 支持的所有规则类型
const ALL_RULE_TYPES = [
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", 
    "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP", "SRC-IP-CIDR", 
    "SRC-PORT", "DST-PORT", "PROCESS-NAME", "PROCESS-PATH", "UID", "NETWORK", "DSCP", 
    "RULE-SET", "AND", "OR", "NOT", "SUB-RULE"
];

// 预置策略
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
    customAppGroups: [], // 自定义策略组
    customGlobalRules: [], // 自定义全局规则 (DIRECT/REJECT等)
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

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || 'Unknown';

    // A. 统计逻辑
    if (subUrl && !action) {
        (async () => {
            try {
                const uaKey = `stat:${Buffer.from(ua).toString('base64')}`;
                await kv.incr(uaKey);
                await kv.expire(uaKey, 86400);
            } catch (e) { console.error("Stats Error:", e); }
        })();
    }

    // B. 管理 API
    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword, previewUrl } = req.body;
        const savedConfig = await kv.get('global_config');
        const currentConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        // 1. 登录
        if (action === 'login') {
            if (authHash === currentPwdHash) return res.json({ success: true, isDefaultPwd: currentPwdHash === DEFAULT_PWD_HASH });
            return res.status(403).json({ success: false, msg: "密码错误" });
        }

        // 2. 恢复出厂设置 (彻底清除)
        if (action === 'factoryReset') {
            await kv.flushall();
            return res.json({ success: true, msg: "♻️ 已恢复出厂设置，所有数据已清除，密码重置为 admin" });
        }

        // 3. 预览生成 (不保存，仅返回 YAML)
        if (action === 'preview') {
            if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "会话失效" });
            try {
                const previewRes = await generateConfig(previewUrl, "ClashMeta", currentConfig, true); // 强制覆写模式
                return res.json({ success: true, data: previewRes });
            } catch (e) { return res.json({ success: false, msg: "生成预览失败: " + e.message }); }
        }

        // --- 鉴权 ---
        if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "会话失效" });

        // 4. 保存配置
        if (action === 'saveConfig') {
            const configToSave = { ...newConfig, passwordHash: currentPwdHash };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "✅ 设置已保存" });
        }

        // 5. 重置配置 (保留密码)
        if (action === 'resetConfig') {
            const resetConfig = { ...DEFAULT_CONFIG, passwordHash: currentPwdHash, uiSettings: currentConfig.uiSettings };
            await kv.set('global_config', resetConfig);
            return res.json({ success: true, msg: "🔄 配置项已重置 (密码及统计保留)" });
        }

        // 6. 清空统计
        if (action === 'clearStats') {
            const keys = await kv.keys('stat:*');
            if (keys.length > 0) await kv.del(...keys);
            return res.json({ success: true, msg: "🧹 统计已清空" });
        }

        // 7. 修改密码
        if (action === 'changePassword') {
            if (!newPassword) return res.status(400).json({ msg: "无效密码" });
            const configToSave = { ...currentConfig, passwordHash: newPassword };
            await kv.set('global_config', configToSave);
            return res.json({ success: true, msg: "密码修改成功" });
        }

        // 8. 获取统计
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
                return res.json({ success: true, data: stats, globalOverwrite: currentConfig.enableOverwrite });
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
        // 兼容性
        if (!currentConfig.customAppGroups) currentConfig.customAppGroups = [];
        if (!currentConfig.customGlobalRules) currentConfig.customGlobalRules = [];
        if (!currentConfig.groupOrder) currentConfig.groupOrder = [...DEFAULT_APP_NAMES];

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // D. 订阅生成 (主入口)
    try {
        const savedConfig = await kv.get('global_config');
        const userConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        
        // 检查是否需要覆写
        const isClash = /clash|mihomo|stash/i.test(ua);
        if (!isClash || !userConfig.enableOverwrite) {
            // 原样返回
            const response = await axios.get(subUrl, { headers: { 'User-Agent': ua }, responseType: 'text', timeout: 10000 });
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
            return res.send(response.data);
        }

        // 执行覆写逻辑
        const yamlResult = await generateConfig(subUrl, ua, userConfig, false);
        
        // 获取原始 header 以保留流量信息
        const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
        if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
        
        res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
        res.send(yamlResult);

    } catch (err) {
        res.status(500).send(`Error: ${err.message}`);
    }
};

// === 核心生成逻辑 (抽离出来供 订阅 和 预览 使用) ===
async function generateConfig(subUrl, ua, userConfig, forceOverwrite) {
    if (!userConfig.customAppGroups) userConfig.customAppGroups = [];
    if (!userConfig.customGlobalRules) userConfig.customGlobalRules = [];
    if (!userConfig.groupOrder) userConfig.groupOrder = [...DEFAULT_APP_NAMES];
    const intervalTime = userConfig.healthCheckInterval || 120;

    const response = await axios.get(subUrl, {
        headers: { 'User-Agent': 'ClashMeta' }, // 伪装成 Clash 获取配置
        responseType: 'text',
        timeout: 10000
    });

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

    userConfig.groupOrder.forEach(groupName => {
        let targetProxies = [];
        if (DEFAULT_APP_NAMES.includes(groupName)) {
            const selectedRegions = userConfig.appGroups[groupName] || [];
            const validProxies = selectedRegions
                .map(regionName => `${regionName} 自动负载`)
                .filter(fullName => lbGroupsOutput.find(g => g.name === fullName));
            targetProxies = validProxies.length > 0 ? validProxies : [];
        } else {
            const customGroup = userConfig.customAppGroups.find(g => g.name === groupName);
            if (customGroup) {
                const selectedRegions = customGroup.targetLBs || [];
                const validProxies = selectedRegions
                    .map(regionName => `${regionName} 自动负载`)
                    .filter(fullName => lbGroupsOutput.find(g => g.name === fullName));
                 targetProxies = validProxies.length > 0 ? validProxies : [];
            }
        }
        targetProxies.push("ReiaNEXT");
        MY_GROUPS.push({ name: groupName, type: "select", proxies: targetProxies });
    });

    MY_GROUPS.push({ name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 });
    MY_GROUPS.push({ name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 });

    config['proxy-groups'] = [...MY_GROUPS, ...lbGroupsOutput];

    // 规则生成：GlobalCustom -> GroupCustom -> Original
    const injectedRules = [];
    
    // 1. 全局自定义规则 (DIRECT, REJECT...)
    userConfig.customGlobalRules.forEach(r => {
        const noResolve = r.noResolve ? ',no-resolve' : '';
        injectedRules.push(`${r.type},${r.value},${r.target}${noResolve}`);
    });

    // 2. 策略组自定义规则
    userConfig.customAppGroups.forEach(cg => {
        if (cg.rules && cg.rules.length > 0) {
            cg.rules.forEach(r => {
                const noResolve = r.noResolve ? ',no-resolve' : '';
                injectedRules.push(`${r.type},${r.value},${cg.name}${noResolve}`);
            });
        }
    });

    config.rules = [...injectedRules, ...(config.rules || [])];

    return yaml.dump(config);
}

// =======================================================================
// E. 前端 HTML
// =======================================================================
function renderAdminPage(config) {
    const dns = config.dnsSettings || DEFAULT_CONFIG.dnsSettings;
    const ui = config.uiSettings || { backgroundImage: "" };
    
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
    <title>NextReia Pro V5</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
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
        .badge-proxy { background-color: #0d6efd; }
        .badge-browser { background-color: #6c757d; }
        /* Checkbox grid fix */
        .checkbox-grid { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
        .rule-type-select { max-width: 140px; }
    </style>
    <script>
        // 主题初始化
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

<!-- 通用规则编辑器 Modal (Groups & Global) -->
<div class="modal fade" id="ruleModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="ruleModalTitle">编辑规则</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <div class="alert alert-info small py-2">规则将插入到订阅最前方，优先生效。</div>
                <div id="rule-list-container"></div>
                <button class="btn btn-sm btn-outline-success mt-2" onclick="addRuleRow()">+ 新增规则</button>
                <div id="modal-target-section" class="mt-3">
                    <hr><h6>目标负载均衡组</h6>
                    <div id="modal-app-choices" class="checkbox-grid"></div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                <button type="button" class="btn btn-primary" onclick="saveRulesFromModal()">保存规则</button>
            </div>
        </div>
    </div>
</div>

<div id="pwd-overlay" style="display:none; z-index:9999;">
    <div style="position:absolute; width:100%; height:100%;" onclick="closePwdModal()"></div>
    <div class="login-box">
        <div id="pwd-close-btn" style="position:absolute;top:10px;right:15px;cursor:pointer;font-size:1.5rem;" onclick="closePwdModal()">&times;</div>
        <h4 class="mb-3 text-warning">⚠️ 修改密码</h4>
        <p id="pwd-warning" class="small text-muted" style="display:none">正在使用默认密码。请立即修改。</p>
        <input type="password" id="new_pwd" class="form-control mb-2" placeholder="新密码">
        <input type="password" id="confirm_pwd" class="form-control mb-3" placeholder="确认新密码">
        <button class="btn btn-warning w-100" onclick="changePassword()">确认修改</button>
    </div>
</div>

<div class="container" id="main-app" style="max-width:950px">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h3 class="fw-bold">🛠️ NextReia Pro V5</h3>
        <div>
            <button class="btn btn-outline-secondary btn-sm me-2" onclick="showChangePwd(false)">修改密码</button>
            <button class="btn btn-danger btn-sm" onclick="doLogout()">退出</button>
        </div>
    </div>

    <ul class="nav nav-tabs mb-4" id="myTab" role="tablist">
        <li class="nav-item"><button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config-pane">⚙️ 配置</button></li>
        <li class="nav-item"><button class="nav-link" id="ui-tab" data-bs-toggle="tab" data-bs-target="#ui-pane">🎨 界面</button></li>
        <li class="nav-item"><button class="nav-link" id="preview-tab" data-bs-toggle="tab" data-bs-target="#preview-pane">👁️ 预览</button></li>
        <li class="nav-item"><button class="nav-link" id="stats-tab" data-bs-toggle="tab" data-bs-target="#stats-pane" onclick="loadStats()">📊 统计</button></li>
    </ul>

    <div class="tab-content">
        <!-- 配置面板 -->
        <div class="tab-pane fade show active" id="config-pane">
            <div class="card border-primary border-2">
                <div class="card-body d-flex justify-content-between align-items-center">
                    <div><h5 class="mb-0 text-primary fw-bold">🔥 全局覆写开关 <span class="help-icon" data-bs-toggle="tooltip" title="关闭时，Clash 客户端将直接获取原订阅，不做任何修改；开启后才会下发覆写后的配置。">?</span></h5></div>
                    <div class="form-check form-switch form-switch-lg"><input class="form-check-input" type="checkbox" role="switch" id="enable_overwrite" style="transform: scale(1.5);" ${config.enableOverwrite ? 'checked' : ''}></div>
                </div>
            </div>

            <!-- 1. 负载均衡 -->
            <div class="card">
                <div class="card-header text-primary bg-body-tertiary">1. 负载均衡组 (Regex) <span class="help-icon" data-bs-toggle="tooltip" title="使用正则表达式从订阅中筛选节点。例如 HK|Hong 匹配所有包含这些字符的节点。">?</span></div>
                <div class="card-body"><div id="lb_area"></div><button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button></div>
            </div>

            <!-- 2. 分流策略 -->
            <div class="card">
                <div class="card-header text-warning bg-body-tertiary d-flex justify-content-between align-items-center">
                    <span>2. 分流策略组 <span class="help-icon" data-bs-toggle="tooltip" title="拖拽可排序。自定义组可编辑规则，默认组仅可调整排序和目标。">?</span></span>
                    <button class="btn btn-sm btn-success" onclick="addNewCustomGroup()">+ 新增自定义组</button>
                </div>
                <div class="card-body"><ul class="list-group" id="sortable-groups"></ul></div>
            </div>

            <!-- 3. 分流目标 -->
            <div class="card"><div class="card-header text-success bg-body-tertiary">3. 分流策略组目标配置</div><div class="card-body" id="app_area"></div></div>

            <!-- 4. DNS -->
            <div class="card">
                <div class="card-header text-info bg-body-tertiary d-flex align-items-center">4. DNS 覆写设置 <span class="badge bg-secondary ms-2">Mihomo Only</span></div>
                <div class="card-body">
                    <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="dns_enable" ${dnsDisplay.enable ? 'checked' : ''}><label class="form-check-label fw-bold">启用 DNS 覆写</label></div>
                    <div class="row g-3">
                        <div class="col-md-6"><label class="form-label small">IPv6</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_ipv6" ${dnsDisplay.ipv6 ? 'checked' : ''}></div></div>
                        <div class="col-md-6"><label class="form-label small">Enhanced Mode</label><select id="dns_enhanced" class="form-select form-select-sm"><option value="fake-ip" ${dnsDisplay['enhanced-mode'] === 'fake-ip' ? 'selected' : ''}>fake-ip</option><option value="redir-host" ${dnsDisplay['enhanced-mode'] === 'redir-host' ? 'selected' : ''}>redir-host</option></select></div>
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

            <!-- 5. 高级设置 -->
            <div class="card">
                <div class="card-header text-secondary bg-body-tertiary">5. 高级设置</div>
                <div class="card-body">
                    <button class="btn btn-outline-dark w-100 mb-3" onclick="openGlobalRuleEditor()">🌐 编辑全局/预置规则 (DIRECT/REJECT...)</button>
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
            
            <div class="d-flex gap-2 mb-5">
                <button class="btn btn-outline-secondary flex-grow-1 p-3" onclick="resetConfig()">⚠️ 重置配置</button>
                <button class="btn btn-success flex-grow-1 p-3 shadow" onclick="save()">保存所有设置</button>
            </div>
        </div>

        <!-- 界面设置 -->
        <div class="tab-pane fade" id="ui-pane">
            <div class="card"><div class="card-header">🎨 个性化</div><div class="card-body"><div class="mb-3"><label class="form-label">背景图片 URL</label><input type="text" id="bg_image" class="form-control" placeholder="https://example.com/bg.jpg" value="${ui.backgroundImage}"></div><button class="btn btn-primary" onclick="save()">保存界面设置</button></div></div>
            <div class="card border-danger"><div class="card-header text-danger">🧨 危险区域</div><div class="card-body"><p class="small">警告：这将彻底清除包括密码、统计数据在内的所有设置，恢复到初始安装状态。</p><button class="btn btn-danger w-100" onclick="factoryReset()">恢复出厂设置</button></div></div>
        </div>

        <!-- 预览实验室 -->
        <div class="tab-pane fade" id="preview-pane">
            <div class="card">
                <div class="card-header">👁️ 预览实验室 (Preview Lab)</div>
                <div class="card-body">
                    <div class="mb-3">
                        <label class="form-label">测试订阅链接</label>
                        <div class="input-group">
                            <input type="text" id="preview_sub_url" class="form-control" placeholder="在此粘贴原始订阅链接...">
                            <button class="btn btn-info" onclick="generatePreview()">生成预览</button>
                        </div>
                    </div>
                    <label class="form-label">YAML 预览 (只读)</label>
                    <textarea id="preview_output" class="form-control bg-light" rows="15" readonly style="font-size:0.8rem;"></textarea>
                </div>
            </div>
        </div>

        <!-- 统计 -->
        <div class="tab-pane fade" id="stats-pane">
            <div class="card"><div class="card-header bg-body-tertiary d-flex justify-content-between align-items-center"><span>📊 24H 统计</span><div><button class="btn btn-sm btn-outline-danger me-2" onclick="clearStats()">清空</button><button class="btn btn-sm btn-outline-secondary" onclick="loadStats()">刷新</button></div></div><div class="card-body"><div class="chart-container d-flex justify-content-center"><canvas id="statsChart"></canvas></div><div id="stats_tables"></div></div></div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

<script>
    // --- Initial Config ---
    let config = ${JSON.stringify(config)};
    let authTokenHash = sessionStorage.getItem('authHash') || "";
    const DEFAULT_APP_NAMES = ${JSON.stringify(DEFAULT_APP_NAMES)};
    const ALL_RULE_TYPES = ${JSON.stringify(ALL_RULE_TYPES)};
    const BUILT_IN_POLICIES = ${JSON.stringify(BUILT_IN_POLICIES)};
    let editingMode = null; // 'group' or 'global'
    let editingGroupName = null;
    let myChart = null;
    
    if(authTokenHash) {
        document.getElementById('login-overlay').style.display = 'none';
        document.getElementById('main-app').classList.add('active');
        renderUI();
    }

    function hash(str) { return CryptoJS.SHA256(str).toString(CryptoJS.enc.Hex); }

    // --- Login & Reset ---
    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value;
        const pwdHash = hash(pwd);
        try {
            const res = await (await fetch('/?action=login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: pwdHash }) })).json();
            if (res.success) {
                authTokenHash = pwdHash; sessionStorage.setItem('authHash', pwdHash);
                document.getElementById('login-overlay').style.display = 'none';
                if (res.isDefaultPwd) showChangePwd(true);
                else { document.getElementById('main-app').classList.add('active'); renderUI(); }
            } else { alert("密码错误"); }
        } catch (e) { alert("网络错误"); }
    }
    document.getElementById('login_pwd').addEventListener('keypress', e => e.key === 'Enter' && doLogin());
    function doLogout() { sessionStorage.removeItem('authHash'); location.reload(); }

    async function factoryReset() { if(!confirm("⚠️ 严重警告：这将彻底清除所有数据(含密码)！")) return; await fetch('/?action=factoryReset', { method: 'POST' }); alert("已恢复出厂设置"); location.reload(); }
    async function resetConfig() { if(!confirm("仅重置配置项(保留密码/统计)？")) return; await fetch('/?action=resetConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) }); alert("配置已重置"); location.reload(); }

    // --- UI Rendering ---
    function renderUI() {
        document.getElementById('lb_area').innerHTML = '';
        config.lbGroups.forEach(val => addLB(val));
        renderSortableGroups();
        renderAppGroups();
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
        new Sortable(list, { handle: '.sort-handle', animation: 150, ghostClass: 'ghost-class', delay: 150, delayOnTouchOnly: true, onEnd: function (evt) { config.groupOrder = Array.from(list.children).map(li => li.dataset.name); renderAppGroups(); } });
    }

    function addNewCustomGroup() {
        const name = prompt("新组名称:", "MyGroup");
        if (name && !config.groupOrder.includes(name)) {
            config.groupOrder.splice(1, 0, name);
            config.customAppGroups.push({ name: name, rules: [], targetLBs: [] });
            renderSortableGroups(); renderAppGroups();
        } else if (name) { alert("名称无效或重复"); }
    }
    function deleteCustomGroup(name) {
        if (!confirm(\`确认删除 \${name} ?\`)) return;
        config.groupOrder = config.groupOrder.filter(n => n !== name);
        config.customAppGroups = config.customAppGroups.filter(g => g.name !== name);
        renderSortableGroups(); renderAppGroups();
    }
    function updateGroupName(oldName, newName) {
        if (oldName === newName || DEFAULT_APP_NAMES.includes(oldName)) return;
        const idx = config.groupOrder.indexOf(oldName);
        if (idx !== -1) config.groupOrder[idx] = newName;
        const grp = config.customAppGroups.find(g => g.name === oldName);
        if (grp) grp.name = newName;
        renderSortableGroups(); renderAppGroups();
    }

    // --- Rule Editor Logic (Unified) ---
    const ruleModal = new bootstrap.Modal(document.getElementById('ruleModal'));
    
    function openRuleEditor(mode, groupName) {
        editingMode = mode;
        editingGroupName = groupName;
        const container = document.getElementById('rule-list-container'); container.innerHTML = '';
        const targetSection = document.getElementById('modal-target-section');
        
        let rules = [];
        if (mode === 'global') {
            document.getElementById('ruleModalTitle').innerText = "全局/预置规则";
            rules = config.customGlobalRules || [];
            targetSection.style.display = 'none'; // 全局规则的目标是 dropdown 选择的，不是多选组
        } else {
            document.getElementById('ruleModalTitle').innerText = groupName;
            const grp = config.customAppGroups.find(g => g.name === groupName);
            rules = grp ? (grp.rules || []) : [];
            targetSection.style.display = 'block';
            // Render LB Choices
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
    
    // 打开全局编辑器入口
    function openGlobalRuleEditor() { openRuleEditor('global'); }

    function addRuleRow(type = 'DOMAIN-SUFFIX', val = '', target = '', noResolve = false) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 rule-row';
        
        // Type Select
        let typeOpts = ALL_RULE_TYPES.map(t => \`<option value="\${t}" \${type===t?'selected':''}>\${t}</option>\`).join('');
        
        // Target Input (For Global, it's a dropdown; For Group, it's hidden/unused here logic handled by checkbox)
        let targetInput = '';
        if (editingMode === 'global') {
            let policyOpts = BUILT_IN_POLICIES.map(p => \`<option value="\${p}" \${target===p?'selected':''}>\${p}</option>\`).join('');
            targetInput = \`<select class="form-select form-select-sm rule-target" style="max-width:120px">\${policyOpts}</select>\`;
        }

        // No-Resolve Checkbox
        let nrCheck = \`<div class="input-group-text"><input class="form-check-input mt-0 rule-no-resolve" type="checkbox" \${noResolve?'checked':''} aria-label="no-resolve"> <span class="small ms-1">no-res</span></div>\`;

        div.innerHTML = \`
            <select class="form-select form-select-sm rule-type rule-type-select">\${typeOpts}</select>
            <input type="text" class="form-control form-control-sm rule-value" placeholder="值 (google.com)" value="\${val}">
            \${targetInput}
            \${nrCheck}
            <button class="btn btn-outline-danger btn-sm" onclick="this.parentElement.remove()">×</button>
        \`;
        document.getElementById('rule-list-container').appendChild(div);
    }

    function saveRulesFromModal() {
        const rows = document.querySelectorAll('.rule-row');
        const newRules = Array.from(rows).map(row => {
            const r = {
                type: row.querySelector('.rule-type').value,
                value: row.querySelector('.rule-value').value,
                noResolve: row.querySelector('.rule-no-resolve').checked
            };
            if (editingMode === 'global') {
                r.target = row.querySelector('.rule-target').value;
            }
            return r;
        }).filter(r => r.value);

        if (editingMode === 'global') {
            config.customGlobalRules = newRules;
        } else {
            const targets = Array.from(document.querySelectorAll('.modal-target-chk:checked')).map(i => i.value);
            const grp = config.customAppGroups.find(g => g.name === editingGroupName);
            if (grp) { grp.rules = newRules; grp.targetLBs = targets; } 
            else { config.customAppGroups.push({ name: editingGroupName, rules: newRules, targetLBs: targets }); }
        }
        
        ruleModal.hide(); 
        if(editingMode !== 'global') renderAppGroups(); 
    }

    // --- App Groups (Mixed) ---
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

    // --- Save & Preview ---
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
        const newConfig = { 
            ...config, lbGroups, appGroups, customAppGroups: updatedCustomGroups, groupOrder: config.groupOrder, dnsSettings, customGlobalRules: config.customGlobalRules,
            includeUnmatched: document.getElementById('unmatched').checked, healthCheckInterval: document.getElementById('interval').value,
            enableOverwrite: document.getElementById('enable_overwrite').checked, uiSettings: { backgroundImage: document.getElementById('bg_image').value }
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
        const url = document.getElementById('preview_sub_url').value;
        if(!url) return alert("请输入订阅链接");
        document.getElementById('preview_output').value = "生成中...";
        try {
            const res = await (await fetch('/?action=preview', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, previewUrl: url }) })).json();
            if(res.success) document.getElementById('preview_output').value = res.data;
            else document.getElementById('preview_output').value = "错误: " + res.msg;
        } catch(e) { document.getElementById('preview_output').value = "网络错误"; }
    }

    // --- Stats & Password ---
    async function loadStats() {
        const res = await (await fetch('/?action=getStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) })).json();
        if (res.success) { renderStats(res.data, res.globalOverwrite); }
    }
    
    let statsSortKey = 'count'; let statsSortAsc = false;
    let currentStatsData = []; let currentIsOverwrite = true;

    function renderStats(data, isOverwriteEnabled) {
        currentStatsData = data; currentIsOverwrite = isOverwriteEnabled;
        const container = document.getElementById('stats_tables'); container.innerHTML = '';
        
        const proxyClients = data.filter(i => /Clash|Mihomo|Stash|Shadowrocket|Surfboard|v2ray/i.test(i.ua));
        const browserClients = data.filter(i => !/Clash|Mihomo|Stash|Shadowrocket|Surfboard|v2ray/i.test(i.ua));
        
        container.innerHTML += createStatsTable("🚀 代理客户端", proxyClients, true);
        container.innerHTML += createStatsTable("🌐 浏览器 / 其他", browserClients, false);
        
        // Chart
        if (myChart) myChart.destroy();
        const ctx = document.getElementById('statsChart').getContext('2d');
        const categoryMap = {};
        data.forEach(item => {
            let simple = "其他";
            if (/Mozilla|Chrome|Safari|Edge/i.test(item.ua) && !/Clash/i.test(item.ua)) simple = "浏览器/非代理";
            else if (/Clash|Mihomo/i.test(item.ua)) simple = "Clash/Mihomo";
            else if (/Shadowrocket/i.test(item.ua)) simple = "Shadowrocket";
            categoryMap[simple] = (categoryMap[simple] || 0) + item.count;
        });
        myChart = new Chart(ctx, { type: 'doughnut', data: { labels: Object.keys(categoryMap), datasets: [{ data: Object.values(categoryMap), backgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0'] }] }, options: { maintainAspectRatio: false } });
    }

    function createStatsTable(title, items, showOverwrite) {
        if (items.length === 0) return '';
        // Sort
        items.sort((a, b) => statsSortKey === 'count' ? (statsSortAsc ? a.count - b.count : b.count - a.count) : (statsSortAsc ? a.ua.localeCompare(b.ua) : b.ua.localeCompare(a.ua)));
        
        let html = \`<h6 class="mt-4">\${title}</h6><div class="table-responsive"><table class="table table-sm table-striped">
            <thead><tr><th onclick="toggleSort('ua')" style="cursor:pointer">UA ↕</th>\${showOverwrite?'<th>覆写状态</th>':''}<th onclick="toggleSort('count')" class="text-end" style="cursor:pointer">次数 ↕</th></tr></thead><tbody>\`;
        items.forEach(i => {
            let status = '';
            if(showOverwrite) {
                const isClash = /Clash|Mihomo|Stash/i.test(i.ua);
                status = \`<td>\${(isClash && currentIsOverwrite) ? '<span class="badge bg-success">✅ 是</span>' : '<span class="badge bg-secondary">❌ 否</span>'}</td>\`;
            }
            html += \`<tr><td class="small text-break">\${i.ua}</td>\${status}<td class="text-end">\${i.count}</td></tr>\`;
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