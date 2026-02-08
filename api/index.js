/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 6.6 (Hotfix & Smart Logic Upgrade)
 */

const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');
const crypto = require('crypto');

function hashPwd(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

const DEFAULT_PWD_HASH = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918";
const DEFAULT_APP_NAMES = ["Sora&ChatGPT", "ABEMA", "赛马娘PrettyDerby", "PJSK-JP", "Claude"];
const ALL_RULE_TYPES = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "GEOSITE", "IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP", "SRC-IP-CIDR", "SRC-PORT", "DST-PORT", "PROCESS-NAME", "PROCESS-PATH", "UID", "NETWORK", "DSCP", "RULE-SET", "AND", "OR", "NOT", "SUB-RULE"];
const BUILT_IN_POLICIES = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"];

const DEFAULT_CONFIG = {
    passwordHash: DEFAULT_PWD_HASH,
    enableOverwrite: true,
    uiSettings: { backgroundImage: "", ipApiSource: "ipapi.co", customIpApiUrl: "" },
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

// -----------------------------------------------------------------------
// 1. 全局请求处理器
// -----------------------------------------------------------------------
module.exports = async (req, res) => {
    try {
        await handleRequest(req, res);
    } catch (err) {
        console.error("Runtime Error:", err);
        res.status(200).setHeader('Content-Type', 'text/html; charset=utf-8');
        res.send('<div style="padding:20px;font-family:sans-serif;"><h3>🔴 服务端错误</h3><pre>' + err.message + '</pre></div>');
    }
};

async function handleRequest(req, res) {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || 'Unknown';
    const clientIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0] : (req.socket.remoteAddress || 'Unknown');

    // 统计逻辑
    if (subUrl && !action) {
        (async () => {
            try {
                await kv.incr('stat:ua:' + Buffer.from(ua).toString('base64'));
                await kv.expire('stat:ua:' + Buffer.from(ua).toString('base64'), 86400);
                await kv.incr('stat:ip:' + clientIp);
                await kv.expire('stat:ip:' + clientIp, 86400);
                await kv.incr('stat:total');
            } catch (e) {}
        })();
    }

    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword, previewUrl, type: statsType } = req.body;
        const savedConfig = await kv.get('global_config');
        const currentConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        if (action === 'login') {
            if (authHash === currentPwdHash) return res.json({ success: true, isDefaultPwd: currentPwdHash === DEFAULT_PWD_HASH });
            return res.status(403).json({ success: false });
        }
        if (action === 'factoryReset') { await kv.flushall(); return res.json({ success: true }); }
        
        if (authHash !== currentPwdHash) return res.status(403).json({ success: false });

        if (action === 'preview') {
            const previewRes = await generateConfig(previewUrl, "ClashMeta", currentConfig);
            return res.json({ success: true, data: previewRes });
        }
        if (action === 'saveConfig') {
            await kv.set('global_config', { ...newConfig, passwordHash: currentPwdHash });
            return res.json({ success: true, msg: "保存成功" });
        }
        if (action === 'resetConfig') {
            await kv.set('global_config', { ...DEFAULT_CONFIG, passwordHash: currentPwdHash, uiSettings: currentConfig.uiSettings });
            return res.json({ success: true });
        }
        if (action === 'clearStats') {
            const keys = await kv.keys('stat:*'); if (keys.length > 0) await kv.del(...keys);
            return res.json({ success: true });
        }
        if (action === 'changePassword') {
            await kv.set('global_config', { ...currentConfig, passwordHash: newPassword });
            return res.json({ success: true });
        }
        if (action === 'getStats') {
            const reqType = statsType || 'ua';
            const keys = await kv.keys(reqType === 'ip' ? 'stat:ip:*' : 'stat:ua:*');
            const total = await kv.get('stat:total') || 0;
            const stats = [];
            if (keys.length > 0) {
                const values = await kv.mget(...keys);
                keys.forEach((k, i) => {
                    let label = k.replace(reqType === 'ip' ? 'stat:ip:' : 'stat:ua:', '');
                    if (reqType === 'ua') label = Buffer.from(label, 'base64').toString('utf-8');
                    stats.push({ label, count: parseInt(values[i] || 0) });
                });
            }
            return res.json({ success: true, data: stats, total, globalOverwrite: currentConfig.enableOverwrite });
        }
    }

    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = { 
            ...DEFAULT_CONFIG, ...savedConfig,
            dnsSettings: { ...DEFAULT_CONFIG.dnsSettings, ...(savedConfig?.dnsSettings || {}) },
            uiSettings: { ...DEFAULT_CONFIG.uiSettings, ...(savedConfig?.uiSettings || {}) }
        };
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // 用户获取订阅逻辑
    const savedConfig = await kv.get('global_config');
    const userConfig = { ...DEFAULT_CONFIG, ...savedConfig };
    const isClash = /clash|mihomo|stash/i.test(ua);
    if (!isClash || !userConfig.enableOverwrite) {
        const response = await axios.get(subUrl, { headers: { 'User-Agent': ua }, responseType: 'text', timeout: 10000 });
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
        return res.send(response.data);
    }
    const yamlResult = await generateConfig(subUrl, ua, userConfig);
    const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
    if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
    res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
    res.send(yamlResult);
}

// -----------------------------------------------------------------------
// 2. 核心 YAML 生成逻辑
// -----------------------------------------------------------------------
async function generateConfig(subUrl, ua, userConfig) {
    const intervalTime = userConfig.healthCheckInterval || 120;
    const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
    let config = yaml.load(response.data);
    const allProxyNames = (config.proxies || []).map(p => p.name);
    
    if (userConfig.dnsSettings?.enable) config.dns = userConfig.dnsSettings;

    const usedNodeNames = new Set();
    const lbGroupsOutput = [];
    userConfig.lbGroups.forEach(group => {
        const regex = new RegExp(group.regex, 'i');
        const matched = allProxyNames.filter(name => regex.test(name));
        matched.forEach(n => usedNodeNames.add(n));
        lbGroupsOutput.push({
            name: group.name + " 自动负载", type: "load-balance", proxies: matched.length > 0 ? matched : ["DIRECT"],
            url: "http://www.gstatic.com/generate_204", interval: parseInt(intervalTime), strategy: "round-robin"
        });
    });

    const unmatchedNodes = allProxyNames.filter(name => !usedNodeNames.has(name));
    const MY_GROUPS = [{ name: "ReiaNEXT", type: "select", proxies: ["♻️ 自动选择", ...lbGroupsOutput.map(g => g.name), "🚫 故障转移", ...(userConfig.includeUnmatched ? unmatchedNodes : [])] }];

    (userConfig.groupOrder || DEFAULT_APP_NAMES).forEach(groupName => {
        let targetProxies = [];
        if (DEFAULT_APP_NAMES.includes(groupName)) {
            const selectedRegions = userConfig.appGroups[groupName] || [];
            targetProxies = selectedRegions.map(r => r + " 自动负载").filter(f => lbGroupsOutput.find(g => g.name === f));
        } else {
            const cg = (userConfig.customAppGroups || []).find(g => g.name === groupName);
            if (cg) targetProxies = (cg.targetLBs || []).map(r => r + " 自动负载").filter(f => lbGroupsOutput.find(g => g.name === f));
        }
        targetProxies.push("ReiaNEXT");
        MY_GROUPS.push({ name: groupName, type: "select", proxies: targetProxies });
    });

    MY_GROUPS.push({ name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 });
    MY_GROUPS.push({ name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 });
    config['proxy-groups'] = [...MY_GROUPS, ...lbGroupsOutput];

    const injectedRules = [];
    (userConfig.customGlobalRules || []).forEach(r => injectedRules.push(r.type + ',' + r.value + ',' + r.target + (r.noResolve ? ',no-resolve' : '')));
    (userConfig.customAppGroups || []).forEach(cg => {
        if (cg.rules) cg.rules.forEach(r => injectedRules.push(r.type + ',' + r.value + ',' + cg.name + (r.noResolve ? ',no-resolve' : '')));
    });
    config.rules = [...injectedRules, ...(config.rules || [])];
    return yaml.dump(config);
}

// -----------------------------------------------------------------------
// 3. 前端 UI 渲染
// -----------------------------------------------------------------------
function renderAdminPage(config) {
    const dns = config.dnsSettings || DEFAULT_CONFIG.dnsSettings;
    const ui = config.uiSettings || { backgroundImage: "", ipApiSource: "ipapi.co" };

    // 修复 dnsDisplay 未定义错误：在函数顶部定义
    const dnsDisplay = {
        ...dns,
        defaultNameserver: (dns['default-nameserver'] || []).join('\n'),
        nameserver: (dns.nameserver || []).join('\n'),
        fallback: (dns.fallback || []).join('\n'),
        ipcidr: (dns['fallback-filter']?.ipcidr || []).join('\n'),
        domain: (dns['fallback-filter']?.domain || []).join('\n')
    };

    const customBgCss = ui.backgroundImage ? 'body { background: linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), url("' + ui.backgroundImage + '") no-repeat center center fixed; background-size: cover; } .card { background-color: rgba(255, 255, 255, 0.9); } [data-bs-theme="dark"] .card { background-color: rgba(33, 37, 41, 0.95); }' : '';

    return `
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia Pro V6.6</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); transition: background-color 0.3s; padding: 20px; min-height: 100vh; padding-top: 60px; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        [data-bs-theme="dark"] .card { box-shadow: 0 4px 12px rgba(0,0,0,0.4); background-color: #2b3035; }
        ${customBgCss}
        .theme-switcher { position: fixed; top: 15px; right: 20px; z-index: 10001; }
        #login-overlay, #pwd-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255, 255, 255, 0.4); backdrop-filter: blur(var(--blur-amt)); z-index: 9998; display: flex; justify-content: center; align-items: center; }
        [data-bs-theme="dark"] #login-overlay, [data-bs-theme="dark"] #pwd-overlay { background: rgba(0, 0, 0, 0.6); }
        .login-box { background: var(--bs-body-bg); padding: 2.5rem; border-radius: 16px; width: 90%; max-width: 420px; text-align: center; border: 1px solid var(--bs-border-color); position: relative; }
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        
        /* 修复复选框错位溢出 */
        .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 10px; width: 100%; max-height: 220px; overflow-y: auto; padding: 15px; border: 1px solid var(--bs-border-color); border-radius: 12px; background: var(--bs-tertiary-bg); }
        .checkbox-grid .form-check { margin: 0; background: var(--bs-body-bg); padding: 8px 10px 8px 30px; border-radius: 6px; border: 1px solid var(--bs-border-color); }
        
        .list-group-item { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
        .sort-handle { cursor: grab; font-size: 1.2rem; color: #adb5bd; padding: 5px; }
        #preview_container { background-color: #1e1e1e; border-radius: 6px; padding: 15px; max-height: 600px; overflow: auto; }
        [data-bs-theme="light"] #preview_container { background-color: #f8f9fa; border: 1px solid #dee2e6; }
    </style>
    <script>
        (() => {
            const getStoredTheme = () => localStorage.getItem('theme');
            const setTheme = theme => {
                const actual = (theme === 'auto') ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
                document.documentElement.setAttribute('data-bs-theme', actual);
            }
            setTheme(getStoredTheme() || 'auto');
            window.addEventListener('DOMContentLoaded', () => {
                document.querySelectorAll('[data-bs-theme-value]').forEach(t => t.addEventListener('click', () => {
                    localStorage.setItem('theme', t.getAttribute('data-bs-theme-value'));
                    location.reload();
                }));
            });
        })();
    </script>
</head>
<body>

<div class="dropdown theme-switcher">
    <button class="btn btn-outline-secondary dropdown-toggle shadow-sm" data-bs-toggle="dropdown">🎨 主题</button>
    <ul class="dropdown-menu dropdown-menu-end shadow">
        <li><button class="dropdown-item" data-bs-theme-value="light">☀️ 浅色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="dark">🌙 深色</button></li>
        <li><button class="dropdown-item" data-bs-theme-value="auto">🖥️ 自动</button></li>
    </ul>
</div>

<div id="login-overlay">
    <div class="login-box">
        <h4>🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg my-3 text-center" placeholder="请输入密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div class="mt-3"><a href="#" class="text-danger small" onclick="factoryReset()">忘记密码? 恢复出厂设置</a></div>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<div class="modal fade" id="ruleModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header"><h5 class="modal-title" id="ruleModalTitle">编辑规则</h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
            <div class="modal-body">
                <ul class="nav nav-tabs mb-3">
                    <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#edit-visual">可视化编辑</button></li>
                    <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#edit-batch">✨ 智能导入</button></li>
                </ul>
                <div class="tab-content">
                    <div class="tab-pane fade show active" id="edit-visual"><div id="rule-list-container"></div><button class="btn btn-sm btn-outline-success mt-2" onclick="addRuleRow()">+ 新增规则</button></div>
                    <div class="tab-pane fade" id="edit-batch">
                        <textarea id="batch-rule-input" class="form-control" rows="10" placeholder="粘贴规则文本，支持注释行和不规范格式..."></textarea>
                        <button class="btn btn-sm btn-info mt-2" onclick="smartBatchImport()">识别并分析规则</button>
                    </div>
                </div>
                <div id="modal-target-section" class="mt-4">
                    <hr><h6>🎯 作用于哪些负载均衡组</h6>
                    <div id="modal-app-choices" class="checkbox-grid"></div>
                </div>
            </div>
            <div class="modal-footer"><button class="btn btn-secondary" data-bs-dismiss="modal">取消</button><button class="btn btn-primary" onclick="saveRulesFromModal()">保存并关闭</button></div>
        </div>
    </div>
</div>

<div id="pwd-overlay" style="display:none; z-index:9999;">
    <div style="position:absolute; width:100%; height:100%;" onclick="closePwdModal()"></div>
    <div class="login-box">
        <div style="position:absolute;top:10px;right:15px;cursor:pointer;font-size:1.5rem;" onclick="closePwdModal()">&times;</div>
        <h4 class="mb-3 text-warning">⚠️ 修改密码</h4>
        <input type="password" id="new_pwd" class="form-control mb-2" placeholder="新密码"><input type="password" id="confirm_pwd" class="form-control mb-3" placeholder="确认新密码"><button class="btn btn-warning w-100" onclick="changePassword()">确认修改</button>
    </div>
</div>

<div class="container" id="main-app" style="max-width:950px">
    <div class="d-flex justify-content-between align-items-center mb-3"><h3>🛠️ NextReia Pro</h3><div><button class="btn btn-outline-secondary btn-sm me-2" onclick="showChangePwd(false)">修改密码</button><button class="btn btn-danger btn-sm" onclick="doLogout()">退出</button></div></div>
    <ul class="nav nav-tabs mb-4" role="tablist">
        <li class="nav-item"><button class="nav-link active" id="config-tab" data-bs-toggle="tab" data-bs-target="#config-pane">⚙️ 配置</button></li>
        <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#ui-pane">🎨 界面</button></li>
        <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#preview-pane">👁️ 预览</button></li>
        <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#stats-pane" onclick="loadStats()">📊 统计</button></li>
    </ul>
    
    <div class="tab-content">
        <div class="tab-pane fade show active" id="config-pane">
            <div class="card border-primary border-2"><div class="card-body d-flex justify-content-between"><div><h5 class="mb-0 text-primary fw-bold">🔥 全局覆写开关</h5></div><div class="form-check form-switch form-switch-lg"><input class="form-check-input" type="checkbox" id="enable_overwrite" style="transform:scale(1.5);" ${config.enableOverwrite ? 'checked' : ''}></div></div></div>
            <div class="card"><div class="card-header text-primary bg-body-tertiary">1. 负载均衡组 (正则筛选节点)</div><div class="card-body"><div id="lb_area"></div><button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button></div></div>
            <div class="card"><div class="card-header text-warning bg-body-tertiary d-flex justify-content-between"><span>2. 分流策略组 (支持排序/新增)</span><button class="btn btn-sm btn-success" onclick="addNewCustomGroup()">+ 新增</button></div><div class="card-body"><ul class="list-group" id="sortable-groups"></ul></div></div>
            <div class="card"><div class="card-header text-success bg-body-tertiary">3. 分流策略对应目标</div><div class="card-body" id="app_area"></div></div>
            <div class="card"><div class="card-header text-info bg-body-tertiary">4. DNS 覆写设置</div><div class="card-body">
                <div class="form-check form-switch mb-3"><input class="form-check-input" type="checkbox" id="dns_enable" ${dns.enable ? 'checked' : ''}><label class="form-check-label fw-bold">启用</label></div>
                <div class="row g-3">
                    <div class="col-md-6"><label class="small">IPv6 开关</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_ipv6" ${dns.ipv6 ? 'checked' : ''}></div></div>
                    <div class="col-md-6"><label class="small">Enhanced Mode</label><select id="dns_enhanced" class="form-select form-select-sm"><option value="fake-ip" ${dns['enhanced-mode']==='fake-ip'?'selected':''}>fake-ip</option><option value="redir-host" ${dns['enhanced-mode']==='redir-host'?'selected':''}>redir-host</option></select></div>
                    <div class="col-md-6"><label class="small">Fake-IP Range</label><input type="text" id="dns_fakeip" class="form-control form-control-sm" value="${dns['fake-ip-range']}"></div>
                    <div class="col-md-6"><label class="small">Use Hosts</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_hosts" ${dns['use-hosts']?'checked':''}></div></div>
                    <div class="col-12"><label class="small">Default Nameserver</label><textarea id="dns_default_ns" class="form-control" rows="2">${dnsDisplay.defaultNameserver}</textarea></div>
                    <div class="col-12"><label class="small">Nameserver</label><textarea id="dns_ns" class="form-control" rows="3">${dnsDisplay.nameserver}</textarea></div>
                    <div class="col-12"><label class="small">Fallback</label><textarea id="dns_fallback" class="form-control" rows="3">${dnsDisplay.fallback}</textarea></div>
                    <div class="col-12"><hr><h6>Fallback Filter</h6></div>
                    <div class="col-md-4"><label class="small">GeoIP</label><div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="dns_geoip" ${dns['fallback-filter'].geoip?'checked':''}></div></div>
                    <div class="col-md-8"><label class="small">IP CIDR</label><textarea id="dns_ipcidr" class="form-control" rows="2">${dnsDisplay.ipcidr}</textarea></div>
                    <div class="col-12"><label class="small">Domain</label><textarea id="dns_domain" class="form-control" rows="3">${dnsDisplay.domain}</textarea></div>
                </div>
            </div></div>
            <div class="card"><div class="card-header text-secondary bg-body-tertiary">5. 高级设置</div><div class="card-body">
                <button class="btn btn-outline-dark w-100 mb-3" onclick="openGlobalRuleEditor()">🌐 编辑全局/预置规则</button>
                <div class="row align-items-center"><label class="col-sm-4">健康检查间隔 (s)</label><div class="col-sm-4"><input type="number" id="interval" class="form-control" value="${config.healthCheckInterval || 120}" min="60"></div></div>
                <div class="form-check form-switch mt-3"><input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}><label>未匹配节点放入 ReiaNEXT</label></div>
            </div></div>
            <div class="d-flex gap-2 mb-5"><button class="btn btn-outline-secondary flex-grow-1" onclick="resetConfig()">⚠️ 重置配置</button><button class="btn btn-success flex-grow-1 shadow" onclick="save()">保存所有设置</button></div>
        </div>
        
        <div class="tab-pane fade" id="ui-pane">
            <div class="card"><div class="card-header">🎨 个性化</div><div class="card-body">
                <label>背景图片 URL</label><input type="text" id="bg_image" class="form-control mb-3" placeholder="https://..." value="${ui.backgroundImage}">
                <hr><label>IP 数据源</label><select id="ip_api_source" class="form-select mb-3" onchange="toggleCustomApi()">
                    <option value="ipapi.co" ${ui.ipApiSource==='ipapi.co'?'selected':''}>ipapi.co (HTTPS)</option>
                    <option value="ip-api.com" ${ui.ipApiSource==='ip-api.com'?'selected':''}>ip-api.com (HTTP)</option>
                    <option value="ip.sb" ${ui.ipApiSource==='ip.sb'?'selected':''}>ip.sb (HTTPS)</option>
                    <option value="custom" ${ui.ipApiSource==='custom'?'selected':''}>自定义</option>
                </select>
                <div id="custom_api_div" style="display:none"><label>自定义 API URL ({ip}占位)</label><input type="text" id="custom_ip_api" class="form-control mb-3" value="${ui.customIpApiUrl || ''}"></div>
                <button class="btn btn-primary" onclick="save()">保存界面设置</button>
            </div></div>
            <div class="card"><div class="card-header bg-info-subtle">💾 备份与导入</div><div class="card-body"><button class="btn btn-outline-primary" onclick="exportSettings()">导出设置</button><button class="btn btn-outline-success ms-2" onclick="document.getElementById('file_import').click()">导入设置</button><input type="file" id="file_import" accept=".json" style="display:none" onchange="importSettings(this)"></div></div>
            <div class="card border-danger"><div class="card-header text-danger">🧨 危险区域</div><div class="card-body"><button class="btn btn-danger w-100" onclick="factoryReset()">系统重置 (恢复初始安装状态)</button></div></div>
        </div>
        
        <div class="tab-pane fade" id="preview-pane"><div class="card"><div class="card-header">👁️ 实时预览</div><div class="card-body"><div class="input-group mb-3"><input type="text" id="preview_sub_url" class="form-control" placeholder="粘贴订阅链接..."><button class="btn btn-info" onclick="generatePreview()">生成预览</button></div><div id="preview_container"><pre><code id="preview_code" class="language-yaml"># 生成后的 YAML 将在这里显示</code></pre></div></div></div></div>
        
        <div class="tab-pane fade" id="stats-pane"><div class="card"><div class="card-header bg-body-tertiary d-flex justify-content-between"><span>📊 使用统计 <span id="total-req" class="badge bg-secondary ms-2"></span></span><div><div class="btn-group me-2"><button class="btn btn-sm btn-outline-primary active" id="btn-ua" onclick="switchStats('ua')">UA 统计</button><button class="btn btn-sm btn-outline-primary" id="btn-ip" onclick="switchStats('ip')">IP 统计</button></div><button class="btn btn-sm btn-outline-danger me-2" onclick="clearStats()">清空</button><button class="btn btn-sm btn-outline-secondary" onclick="loadStats()">刷新</button></div></div><div class="card-body"><div class="chart-container d-flex justify-content-center"><canvas id="statsChart" style="max-height:250px;"></canvas></div><div id="stats_tables"></div></div></div></div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-yaml.min.js"></script>

<script>
    let config = ${JSON.stringify(config)};
    let authTokenHash = sessionStorage.getItem('authHash') || "";
    const DEFAULT_APP_NAMES = ${JSON.stringify(DEFAULT_APP_NAMES)};
    const ALL_RULE_TYPES = ${JSON.stringify(ALL_RULE_TYPES)};
    const BUILT_IN_POLICIES = ${JSON.stringify(BUILT_IN_POLICIES)};
    let editingMode = null, editingGroupName = null, myChart = null, currentStatsType = 'ua', statsSortKey = 'count', statsSortAsc = false, currentStatsData = [];

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
    function doLogout() { sessionStorage.clear(); location.reload(); }
    async function factoryReset() { if(!confirm("彻底清除所有数据？")) return; await fetch('/?action=factoryReset', { method: 'POST' }); doLogout(); }

    function renderUI() {
        document.getElementById('lb_area').innerHTML = ''; config.lbGroups.forEach(v => addLB(v));
        renderSortableGroups(); renderAppGroups(); toggleCustomApi();
    }
    function toggleCustomApi() { document.getElementById('custom_api_div').style.display = (document.getElementById('ip_api_source').value === 'custom') ? 'block' : 'none'; }

    function renderSortableGroups() {
        const list = document.getElementById('sortable-groups'); list.innerHTML = '';
        (config.groupOrder || DEFAULT_APP_NAMES).forEach(name => {
            const isDefault = DEFAULT_APP_NAMES.includes(name);
            const li = document.createElement('li'); li.className = 'list-group-item p-2'; li.dataset.name = name;
            let btns = isDefault ? '<span class="badge bg-secondary">默认组</span>' : '<div><button class="btn btn-sm btn-outline-primary" onclick="openRuleEditor(\\'group\\', \\''+name+'\\')">规则</button><button class="btn btn-sm btn-outline-danger ms-1" onclick="deleteCustomGroup(\\''+name+'\\')">删</button></div>';
            li.innerHTML = '<div class="d-flex align-items-center flex-grow-1"><span class="sort-handle me-2 text-primary">☰</span><input type="text" class="form-control form-control-sm me-2" style="max-width:150px;" value="'+name+'" '+(isDefault?'disabled':'')+' onchange="updateGroupName(\\''+name+'\\', this.value)">'+btns+'</div>';
            list.appendChild(li);
        });
        new Sortable(list, { handle: '.sort-handle', animation: 150, onEnd: () => { config.groupOrder = Array.from(list.children).map(li => li.dataset.name); renderAppGroups(); } });
    }

    function addNewCustomGroup() { const n = prompt("新组名:"); if(n && !config.groupOrder.includes(n)) { config.groupOrder.push(n); config.customAppGroups.push({ name: n, rules: [], targetLBs: [] }); renderSortableGroups(); renderAppGroups(); } }
    function deleteCustomGroup(n) { if(confirm("删除 "+n+"?")) { config.groupOrder = config.groupOrder.filter(x => x!==n); config.customAppGroups = config.customAppGroups.filter(x => x.name!==n); renderSortableGroups(); renderAppGroups(); } }
    function updateGroupName(o, n) { if(o===n || DEFAULT_APP_NAMES.includes(o)) return; const i = config.groupOrder.indexOf(o); if(i!==-1) config.groupOrder[i] = n; const g = config.customAppGroups.find(x => x.name===o); if(g) g.name = n; renderSortableGroups(); renderAppGroups(); }

    const ruleModal = new bootstrap.Modal(document.getElementById('ruleModal'));
    function openRuleEditor(mode, name) {
        editingMode = mode; editingGroupName = name;
        document.getElementById('ruleModalTitle').innerText = mode === 'global' ? "全局/预置规则" : name;
        document.getElementById('rule-list-container').innerHTML = ''; document.getElementById('batch-rule-input').value = '';
        const targetSection = document.getElementById('modal-target-section');
        let rules = mode === 'global' ? (config.customGlobalRules || []) : ((config.customAppGroups.find(g => g.name === name) || {}).rules || []);
        targetSection.style.display = mode === 'global' ? 'none' : 'block';
        if (mode !== 'global') {
            const container = document.getElementById('modal-app-choices'); container.innerHTML = '';
            const targets = (config.customAppGroups.find(g => g.name === name) || {}).targetLBs || [];
            getLBNames().forEach(lb => {
                const chk = targets.includes(lb) ? 'checked' : '';
                container.innerHTML += '<div class="form-check border p-2 rounded"><input class="form-check-input" type="checkbox" id="chk_'+lb+'" value="'+lb+'" '+chk+'><label class="form-check-label small w-100" for="chk_'+lb+'">'+lb+'</label></div>';
            });
        }
        rules.forEach(r => addRuleRow(r.type, r.value, r.target, r.noResolve));
        ruleModal.show();
    }

    function smartBatchImport() {
        const text = document.getElementById('batch-rule-input').value;
        const lines = text.split('\\n'); let c = 0;
        lines.forEach(l => {
            let s = l.trim(); if(!s || s.startsWith('#') || s.startsWith('//')) return;
            if(s.startsWith('-')) s = s.substring(1).trim();
            const p = s.split(',').map(x => x.trim());
            if(p.length >= 2) {
                const typeRaw = p[0].toUpperCase().replace(/-/g, '');
                const type = ALL_RULE_TYPES.find(std => std.replace(/-/g, '') === typeRaw) || p[0].toUpperCase();
                if(ALL_RULE_TYPES.includes(type)) {
                    let target = (editingMode === 'global') ? (p[2] || 'DIRECT').toUpperCase() : editingGroupName;
                    addRuleRow(type, p[1], target, l.toLowerCase().includes('no-resolve')); c++;
                }
            }
        });
        alert('智能识别出 ' + c + ' 条规则并导入可视化区域');
        new bootstrap.Tab(document.querySelector('button[data-bs-target="#edit-visual"]')).show();
    }

    function addRuleRow(type = 'DOMAIN-SUFFIX', val = '', target = '', noResolve = false) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 rule-row';
        let typeOpts = ALL_RULE_TYPES.map(t => '<option value="'+t+'" '+(type===t?'selected':'')+'>'+t+'</option>').join('');
        let targetInput = (editingMode === 'global') ? '<select class="form-select form-select-sm rule-target" style="max-width:120px">'+BUILT_IN_POLICIES.map(p => '<option value="'+p+'" '+(target===p?'selected':'')+'>'+p+'</option>').join('')+'</select>' : '';
        let nrCheck = '<div class="input-group-text"><input class="form-check-input mt-0 rule-no-resolve" type="checkbox" '+(noResolve?'checked':'')+'> <span class="small ms-1">no-res</span></div>';
        div.innerHTML = '<select class="form-select form-select-sm rule-type" style="max-width:140px">'+typeOpts+'</select><input type="text" class="form-control form-control-sm rule-value" value="'+val+'">'+targetInput+nrCheck+'<button class="btn btn-outline-danger btn-sm" onclick="this.parentElement.remove()">×</button>';
        document.getElementById('rule-list-container').appendChild(div);
    }

    function saveRulesFromModal() {
        const newRules = Array.from(document.querySelectorAll('.rule-row')).map(row => ({
            type: row.querySelector('.rule-type').value,
            value: row.querySelector('.rule-value').value,
            noResolve: row.querySelector('.rule-no-resolve').checked,
            target: editingMode === 'global' ? row.querySelector('.rule-target').value : ''
        })).filter(r => r.value);
        if (editingMode === 'global') { config.customGlobalRules = newRules; } 
        else {
            const targets = Array.from(document.querySelectorAll('#modal-app-choices input:checked')).map(i => i.value);
            const grp = config.customAppGroups.find(g => g.name === editingGroupName);
            if (grp) { grp.rules = newRules; grp.targetLBs = targets; } else { config.customAppGroups.push({ name: editingGroupName, rules: newRules, targetLBs: targets }); }
        }
        ruleModal.hide(); renderAppGroups();
    }

    function renderAppGroups() {
        const container = document.getElementById('app_area'); container.innerHTML = '';
        (config.groupOrder || DEFAULT_APP_NAMES).forEach(name => {
            const isDefault = DEFAULT_APP_NAMES.includes(name);
            const row = document.createElement('div'); row.className = 'app-row p-2 border-bottom'; row.dataset.app = name;
            let selected = isDefault ? (config.appGroups[name] || []) : ((config.customAppGroups.find(g => g.name === name) || {}).targetLBs || []);
            let html = '<div class="fw-bold mb-2">'+name+' '+(isDefault?'':'<small class="text-info">(自定义)</small>')+'</div><div class="checkbox-grid">';
            getLBNames().forEach(lb => {
                const chk = selected.includes(lb) ? 'checked' : '';
                html += '<div class="form-check"><input class="form-check-input" type="checkbox" id="'+name+'_'+lb+'" value="'+lb+'" '+chk+'><label class="form-check-label small w-100" for="'+name+'_'+lb+'">'+lb+'</label></div>';
            });
            container.innerHTML += row.outerHTML.replace('</div>', html + '</div></div>');
        });
    }

    function getLBNames() { const names = []; document.querySelectorAll('.lb-n').forEach(i => { if(i.value) names.push(i.value); }); return names.length > 0 ? names : config.lbGroups.map(g => g.name); }
    function addLB(v = {name:'', regex:''}) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 lb-item';
        div.innerHTML = '<input type="text" class="form-control lb-n" value="'+v.name+'"><input type="text" class="form-control lb-r" value="'+v.regex+'"><button class="btn btn-danger" onclick="this.parentElement.remove(); renderAppGroups();">×</button>';
        document.getElementById('lb_area').appendChild(div);
    }

    async function save() {
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({ name: el.querySelector('.lb-n').value, regex: el.querySelector('.lb-r').value })).filter(i=>i.name);
        const appGroups = {}; const updatedCustomGroups = [...config.customAppGroups];
        document.querySelectorAll('.app-row').forEach(row => {
            const n = row.dataset.app, s = Array.from(row.querySelectorAll('input:checked')).map(i=>i.value);
            if (DEFAULT_APP_NAMES.includes(n)) appGroups[n] = s; else { const g = updatedCustomGroups.find(x => x.name === n); if(g) g.targetLBs = s; }
        });
        const split = (id) => document.getElementById(id).value.split('\\n').map(s=>s.trim()).filter(s=>s);
        const newConfig = { 
            ...config, lbGroups, appGroups, customAppGroups: updatedCustomGroups, groupOrder: config.groupOrder,
            dnsSettings: {
                enable: document.getElementById('dns_enable').checked, ipv6: document.getElementById('dns_ipv6').checked,
                'default-nameserver': split('dns_default_ns'), 'enhanced-mode': document.getElementById('dns_enhanced').value,
                'fake-ip-range': document.getElementById('dns_fakeip').value, 'use-hosts': document.getElementById('dns_hosts').checked,
                nameserver: split('dns_ns'), fallback: split('dns_fallback'),
                'fallback-filter': { geoip: document.getElementById('dns_geoip').checked, ipcidr: split('dns_ipcidr'), domain: split('dns_domain') }
            },
            includeUnmatched: document.getElementById('unmatched').checked, healthCheckInterval: document.getElementById('interval').value,
            enableOverwrite: document.getElementById('enable_overwrite').checked,
            uiSettings: { backgroundImage: document.getElementById('bg_image').value, ipApiSource: document.getElementById('ip_api_source').value, customIpApiUrl: document.getElementById('custom_ip_api').value }
        };
        const resp = await fetch('/?action=saveConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newConfig }) });
        alert((await resp.json()).msg); location.reload();
    }

    async function generatePreview() {
        const url = document.getElementById('preview_sub_url').value; if(!url) return alert("URL?");
        document.getElementById('preview_code').textContent = "生成中...";
        try {
            const res = await (await fetch('/?action=preview', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, previewUrl: url }) })).json();
            if(res.success) { document.getElementById('preview_code').textContent = res.data; Prism.highlightElement(document.getElementById('preview_code')); } 
            else alert(res.msg);
        } catch(e) { alert("Fail"); }
    }

    function switchStats(t) { currentStatsType = t; document.getElementById('btn-ua').classList.toggle('active', t==='ua'); document.getElementById('btn-ip').classList.toggle('active', t==='ip'); loadStats(); }
    async function loadStats() {
        const res = await (await fetch('/?action=getStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, type: currentStatsType }) })).json();
        if (res.success) { document.getElementById('total-req').innerText = '总计: ' + res.total; currentStatsData = res.data; renderStats(res.data, res.globalOverwrite); }
    }
    function renderStats(data, isOver) {
        const container = document.getElementById('stats_tables'); container.innerHTML = '';
        if (!data || data.length === 0) return container.innerHTML = '<div class="text-center py-5">暂无统计数据</div>';
        if (currentStatsType === 'ua') {
            const p = data.filter(i => /Clash|Mihomo|Stash|Shadowrocket/i.test(i.label)), b = data.filter(i => !/Clash|Mihomo|Stash|Shadowrocket/i.test(i.label));
            container.innerHTML += createStatsTable("🚀 代理客户端", p, true, isOver); container.innerHTML += createStatsTable("🌐 浏览器 / 其他", b, false);
        } else { container.innerHTML += createStatsTable("📍 来源 IP", data, false); }
        if (myChart) myChart.destroy();
        const ctx = document.getElementById('statsChart').getContext('2d');
        const labels = data.slice(0,6).map(i => i.label.substring(0,15)), counts = data.slice(0,6).map(i => i.count);
        myChart = new Chart(ctx, { type: 'doughnut', data: { labels, datasets: [{ data: counts, backgroundColor: ['#36A2EB', '#FF6384', '#FFCE56', '#4BC0C0', '#9966FF'] }] }, options: { maintainAspectRatio: false } });
    }
    function createStatsTable(t, items, isO, isOver) {
        if(items.length===0) return '';
        items.sort((a,b) => statsSortKey==='count' ? (statsSortAsc?a.count-b.count:b.count-a.count) : (statsSortAsc?a.label.localeCompare(b.label):b.label.localeCompare(a.label)));
        let h = '<h6 class="mt-4">'+t+'</h6><table class="table table-sm small"><thead><tr><th onclick="toggleSort(\\'ua\\')" style="cursor:pointer">LABEL ↕</th>'+(isO?'<th>覆写</th>':'')+'<th onclick="toggleSort(\\'count\\')" style="cursor:pointer">次数 ↕</th></tr></thead><tbody>';
        items.forEach(i => h += '<tr><td class="text-break">'+i.label+'</td>'+(isO?'<td>'+(isOver?'✅':'❌')+'</td>':'')+'<td class="text-end">'+i.count+'</td></tr>');
        return h + '</tbody></table>';
    }
    function toggleSort(k) { statsSortKey = k; statsSortAsc = !statsSortAsc; renderStats(currentStatsData, true); }
    async function clearStats() { if(confirm("清空统计?")) { await fetch('/?action=clearStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) }); loadStats(); } }
    function openGlobalRuleEditor() { openRuleEditor('global'); }
    function showChangePwd(f) { document.getElementById('pwd-overlay').style.display='flex'; }
    function closePwdModal() { document.getElementById('pwd-overlay').style.display='none'; }
    function exportSettings() { const d = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(config)); const a = document.createElement('a'); a.href=d; a.download="nextreia_backup.json"; a.click(); }
    function importSettings(i) { const f = i.files[0]; const r = new FileReader(); r.onload = async (e) => { const n = JSON.parse(e.target.result); await fetch('/?action=saveConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newConfig: {...n, passwordHash:config.passwordHash} }) }); location.reload(); }; r.readAsText(f); }
</script>
</body>
</html>`;
}