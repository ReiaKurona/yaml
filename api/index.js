/**
 * NextReia Clash Subscription Converter & Manager
 * Version: 6.8 (Fixed & Optimized)
 */

const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');
const crypto = require('crypto');

// === 1. 基础工具与常量 ===

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
    uiSettings: { backgroundImage: "", ipApiSource: "ipapi.co", customIpApiUrl: "" },
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

// 合并配置的辅助函数
function mergeConfig(saved) {
    if (!saved) return DEFAULT_CONFIG;
    return {
        ...DEFAULT_CONFIG,
        ...saved,
        uiSettings: { ...DEFAULT_CONFIG.uiSettings, ...(saved.uiSettings || {}) },
        dnsSettings: { 
            ...DEFAULT_CONFIG.dnsSettings, 
            ...(saved.dnsSettings || {}),
            'fallback-filter': { ...DEFAULT_CONFIG.dnsSettings['fallback-filter'], ...(saved.dnsSettings?.['fallback-filter'] || {}) }
        },
        appGroups: { ...DEFAULT_CONFIG.appGroups, ...(saved.appGroups || {}) }
    };
}

module.exports = async (req, res) => {
    try {
        await handleRequest(req, res);
    } catch (err) {
        console.error("Fatal Error:", err);
        res.status(200).send(`<div style="padding:20px;"><h3>🔴 Server Error</h3><pre>${err.message}</pre></div>`);
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
                const uaKey = `stat:ua:${Buffer.from(ua).toString('base64')}`;
                await kv.incr(uaKey); await kv.expire(uaKey, 86400);
                const ipKey = `stat:ip:${clientIp}`;
                await kv.incr(ipKey); await kv.expire(ipKey, 86400);
                await kv.incr('stat:total');
            } catch (e) {}
        })();
    }

    if (req.method === 'POST') {
        const { authHash, newConfig, newPassword, previewUrl, type: statsType } = req.body;
        const savedConfig = await kv.get('global_config');
        const currentConfig = mergeConfig(savedConfig);
        const currentPwdHash = currentConfig.passwordHash || DEFAULT_PWD_HASH;

        if (action === 'login') {
            if (authHash === currentPwdHash) return res.json({ success: true, isDefaultPwd: currentPwdHash === DEFAULT_PWD_HASH });
            return res.status(403).json({ success: false, msg: "密码错误" });
        }
        if (action === 'factoryReset') {
            await kv.flushall();
            return res.json({ success: true, msg: "系统已重置" });
        }
        
        if (authHash !== currentPwdHash) return res.status(403).json({ success: false, msg: "Auth Fail" });

        if (action === 'preview') {
            try {
                const { yamlResult } = await generateConfig(previewUrl, currentConfig);
                return res.json({ success: true, data: yamlResult });
            } catch (e) { return res.json({ success: false, msg: e.message }); }
        }
        if (action === 'saveConfig') {
            await kv.set('global_config', { ...newConfig, passwordHash: currentPwdHash });
            return res.json({ success: true, msg: "保存成功" });
        }
        if (action === 'resetConfig') {
            const reset = { ...DEFAULT_CONFIG, passwordHash: currentPwdHash, uiSettings: currentConfig.uiSettings };
            await kv.set('global_config', reset);
            return res.json({ success: true, msg: "配置重置成功" });
        }
        if (action === 'clearStats') {
            const keys = await kv.keys('stat:*');
            if (keys.length > 0) await kv.del(...keys);
            return res.json({ success: true, msg: "统计已清空" });
        }
        if (action === 'changePassword') {
            await kv.set('global_config', { ...currentConfig, passwordHash: newPassword });
            return res.json({ success: true, msg: "密码修改成功" });
        }
        if (action === 'getStats') {
            const reqType = statsType || 'ua';
            const keys = await kv.keys(reqType === 'ip' ? 'stat:ip:*' : 'stat:ua:*');
            const total = await kv.get('stat:total') || 0;
            let stats = [];
            if (keys.length > 0) {
                const vals = await kv.mget(...keys);
                keys.forEach((k, i) => {
                    let label = k.replace(reqType === 'ip' ? 'stat:ip:' : 'stat:ua:', '');
                    if (reqType === 'ua') { try { label = Buffer.from(label, 'base64').toString('utf-8'); } catch(e){} }
                    stats.push({ label, count: parseInt(vals[i] || 0) });
                });
            }
            return res.json({ success: true, data: stats, total, globalOverwrite: currentConfig.enableOverwrite });
        }
    }

    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        return res.setHeader('Content-Type', 'text/html; charset=utf-8').send(renderAdminPage(mergeConfig(savedConfig)));
    }

    // 订阅转换核心
    const savedConfig = await kv.get('global_config');
    const userConfig = mergeConfig(savedConfig);
    const isClash = /clash|mihomo|stash/i.test(ua);
    
    try {
        if (!isClash || !userConfig.enableOverwrite) {
            const resp = await axios.get(subUrl, { headers: { 'User-Agent': ua }, timeout: 10000 });
            if (resp.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', resp.headers['subscription-userinfo']);
            return res.setHeader('Content-Type', 'text/plain; charset=utf-8').send(resp.data);
        }
        const { yamlResult, userInfo } = await generateConfig(subUrl, userConfig);
        if (userInfo) res.setHeader('subscription-userinfo', userInfo);
        res.setHeader('Content-Type', 'text/yaml; charset=utf-8').send(yamlResult);
    } catch(e) {
        res.status(500).send("Error: " + e.message);
    }
}

async function generateConfig(subUrl, userConfig) {
    const response = await axios.get(subUrl, { headers: { 'User-Agent': 'ClashMeta' }, responseType: 'text', timeout: 10000 });
    let config = yaml.load(response.data);
    const allProxyNames = (config.proxies || []).map(p => p.name);
    const intervalTime = parseInt(userConfig.healthCheckInterval) || 120;

    if (userConfig.dnsSettings?.enable) config.dns = userConfig.dnsSettings;

    const usedNodeNames = new Set();
    const lbGroupsOutput = [];
    (userConfig.lbGroups || []).forEach(group => {
        const regex = new RegExp(group.regex, 'i');
        const matched = allProxyNames.filter(name => regex.test(name));
        if (matched.length > 0) {
            matched.forEach(n => usedNodeNames.add(n));
            lbGroupsOutput.push({
                name: `${group.name} 自动负载`, type: "load-balance", proxies: matched,
                url: "http://www.gstatic.com/generate_204", interval: intervalTime, strategy: "round-robin"
            });
        }
    });

    const unmatchedNodes = allProxyNames.filter(name => !usedNodeNames.has(name));
    const MY_GROUPS = [{ 
        name: "ReiaNEXT", type: "select", 
        proxies: ["♻️ 自动选择", ...lbGroupsOutput.map(g => g.name), "🚫 故障转移", ...(userConfig.includeUnmatched ? unmatchedNodes : [])] 
    }];

    (userConfig.groupOrder || []).forEach(groupName => {
        let targetProxies = [];
        if (DEFAULT_APP_NAMES.includes(groupName)) {
            const selectedRegions = userConfig.appGroups[groupName] || [];
            targetProxies = selectedRegions.map(r => `${r} 自动负载`).filter(f => lbGroupsOutput.find(g => g.name === f));
        } else {
            const customGroup = (userConfig.customAppGroups || []).find(g => g.name === groupName);
            if (customGroup) {
                targetProxies = (customGroup.targetLBs || []).map(r => `${r} 自动负载`).filter(f => lbGroupsOutput.find(g => g.name === f));
            }
        }
        targetProxies.push("ReiaNEXT");
        MY_GROUPS.push({ name: groupName, type: "select", proxies: targetProxies });
    });

    MY_GROUPS.push({ name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 });
    MY_GROUPS.push({ name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 });

    config['proxy-groups'] = [...MY_GROUPS, ...lbGroupsOutput];
    const injectedRules = [];
    (userConfig.customGlobalRules || []).forEach(r => injectedRules.push(`${r.type},${r.value},${r.target}${r.noResolve ? ',no-resolve' : ''}`));
    (userConfig.customAppGroups || []).forEach(cg => {
        (cg.rules || []).forEach(r => injectedRules.push(`${r.type},${r.value},${cg.name}${r.noResolve ? ',no-resolve' : ''}`));
    });
    
    config.rules = [...injectedRules, ...(config.rules || [])];
    return { yamlResult: yaml.dump(config), userInfo: response.headers['subscription-userinfo'] };
}

function renderAdminPage(config) {
    const ui = config.uiSettings;
    const customBgCss = ui.backgroundImage ? 
        `body { background: linear-gradient(rgba(0,0,0,0.6), rgba(0,0,0,0.6)), url('${ui.backgroundImage}') no-repeat center center fixed; background-size: cover; }
         .card { background-color: rgba(255, 255, 255, 0.9); }
         [data-bs-theme="dark"] .card { background-color: rgba(33, 37, 41, 0.95); }` : '';

    return `
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia Pro V6.8</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
    <script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); transition: background 0.3s; padding: 20px; min-height: 100vh; padding-top: 60px; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        [data-bs-theme="dark"] .card { background-color: #2b3035; }
        ${customBgCss}
        #login-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255,255,255,0.4); backdrop-filter: blur(var(--blur-amt)); z-index: 9998; display: flex; justify-content: center; align-items: center; }
        [data-bs-theme="dark"] #login-overlay { background: rgba(0,0,0,0.6); }
        .login-box { background: var(--bs-body-bg); padding: 2.5rem; border-radius: 16px; width: 90%; max-width: 420px; text-align: center; border: 1px solid var(--bs-border-color); }
        #main-app { filter: blur(8px); pointer-events: none; transition: filter 0.3s; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        .checkbox-grid { display: flex; flex-wrap: wrap; gap: 10px; }
    </style>
</head>
<body>
<div id="login-overlay">
    <div class="login-box">
        <h4>🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control mb-3 text-center" placeholder="请输入密码">
        <button class="btn btn-primary w-100" onclick="doLogin()">进入后台</button>
    </div>
</div>

<div class="container" id="main-app" style="max-width:950px">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h3>🛠️ NextReia Pro V6.8</h3>
        <button class="btn btn-danger btn-sm" onclick="doLogout()">退出</button>
    </div>

    <ul class="nav nav-tabs mb-4">
        <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#config-pane">⚙️ 配置</button></li>
        <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#stats-pane" onclick="loadStats()">📊 统计</button></li>
    </ul>

    <div class="tab-content">
        <div class="tab-pane fade show active" id="config-pane">
            <div class="card border-primary"><div class="card-body d-flex justify-content-between">
                <span>🔥 全局覆写开关</span>
                <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="enable_overwrite"></div>
            </div></div>
            <div class="card"><div class="card-header">1. 负载均衡组 (Regex)</div><div class="card-body"><div id="lb_area"></div><button class="btn btn-sm btn-outline-primary" onclick="addLB()">+ 增加</button></div></div>
            <div class="card"><div class="card-header d-flex justify-content-between">2. 分流策略组 <button class="btn btn-sm btn-success" onclick="addNewCustomGroup()">+ 新增</button></div><div class="card-body"><ul class="list-group" id="sortable-groups"></ul></div></div>
            <div class="card"><div class="card-header">3. 节点选择目标</div><div class="card-body" id="app_area"></div></div>
            <div class="card" id="dns_fields">
                <div class="card-header">4. DNS 设置</div>
                <div class="card-body">
                    <div class="form-check form-switch mb-2"><input class="form-check-input" type="checkbox" id="dns_enable"><label>启用</label></div>
                    <div class="row g-2">
                        <div class="col-6"><label class="small">Enhanced Mode</label><select id="dns_enhanced" class="form-select form-select-sm"><option value="fake-ip">fake-ip</option><option value="redir-host">redir-host</option></select></div>
                        <div class="col-6"><label class="small">IPv6</label><input type="checkbox" class="form-check-input d-block" id="dns_ipv6"></div>
                        <div class="col-12"><label class="small">Nameservers (每行一个)</label><textarea id="dns_ns" class="form-control" rows="3"></textarea></div>
                    </div>
                </div>
            </div>
            <div class="card"><div class="card-header">5. 高级</div><div class="card-body">
                <button class="btn btn-outline-dark w-100 mb-2" onclick="openGlobalRuleEditor()">🌐 编辑全局规则</button>
                <div class="input-group mb-2"><span class="input-group-text">健康检查间隔</span><input type="number" id="interval" class="form-control"></div>
            </div></div>
            <button class="btn btn-success w-100 p-3 mb-5" onclick="save()">保存所有设置</button>
        </div>
        <div class="tab-pane fade" id="stats-pane">
            <div id="stats_tables" class="p-3">正在加载...</div>
        </div>
    </div>
</div>

<div class="modal fade" id="ruleModal" tabindex="-1">
    <div class="modal-dialog modal-lg"><div class="modal-content">
        <div class="modal-header"><h5 id="ruleModalTitle"></h5><button class="btn-close" data-bs-dismiss="modal"></button></div>
        <div class="modal-body"><div id="rule-list-container"></div><button class="btn btn-sm btn-outline-success" onclick="addRuleRow()">+ 规则</button></div>
        <div class="modal-footer"><button class="btn btn-primary" onclick="saveRulesFromModal()">确定</button></div>
    </div></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
<script>
    let config = ${JSON.stringify(config)};
    let authTokenHash = sessionStorage.getItem('authHash') || "";
    const DEFAULT_APP_NAMES = ${JSON.stringify(DEFAULT_APP_NAMES)};
    const ALL_RULE_TYPES = ${JSON.stringify(ALL_RULE_TYPES)};
    const BUILT_IN_POLICIES = ${JSON.stringify(BUILT_IN_POLICIES)};
    let editingMode = null; let editingGroupName = null;

    function hash(str) { return CryptoJS.SHA256(str).toString(CryptoJS.enc.Hex); }

    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value; const pwdHash = hash(pwd);
        const res = await fetch('/?action=login', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: pwdHash }) }).then(r => r.json());
        if (res.success) { authTokenHash = pwdHash; sessionStorage.setItem('authHash', pwdHash); location.reload(); } else alert("错误");
    }
    if(authTokenHash) { document.getElementById('login-overlay').style.display = 'none'; document.getElementById('main-app').classList.add('active'); renderUI(); }

    function renderUI() {
        document.getElementById('enable_overwrite').checked = config.enableOverwrite;
        config.lbGroups.forEach(v => addLB(v));
        renderSortableGroups(); renderAppGroups(); renderDNS();
        document.getElementById('interval').value = config.healthCheckInterval;
    }

    function renderDNS() {
        const d = config.dnsSettings;
        document.getElementById('dns_enable').checked = d.enable;
        document.getElementById('dns_ipv6').checked = d.ipv6;
        document.getElementById('dns_enhanced').value = d['enhanced-mode'];
        document.getElementById('dns_ns').value = d.nameserver.join('\\n');
    }

    function addLB(v = {name:'', regex:''}) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 lb-item';
        div.innerHTML = '<input type="text" class="form-control lb-n" value="'+v.name+'"><input type="text" class="form-control lb-r" value="'+v.regex+'"><button class="btn btn-danger" onclick="this.parentElement.remove()">×</button>';
        document.getElementById('lb_area').appendChild(div);
    }

    function renderSortableGroups() {
        const list = document.getElementById('sortable-groups'); list.innerHTML = '';
        config.groupOrder.forEach(name => {
            const isDefault = DEFAULT_APP_NAMES.includes(name);
            const li = document.createElement('li'); li.className = 'list-group-item d-flex justify-content-between align-items-center';
            li.innerHTML = '<span>☰ '+name+'</span><div>' + (isDefault?'':'<button class="btn btn-sm btn-outline-primary me-1" onclick="openRuleEditor(\\'group\\',\\''+name+'\\')">规则</button><button class="btn btn-sm btn-outline-danger" onclick="deleteGroup(\\''+name+'\\')">删</button>') + '</div>';
            list.appendChild(li);
        });
        new Sortable(list, { animation: 150, onEnd: () => { config.groupOrder = Array.from(list.children).map(li => li.innerText.replace('☰ ','').trim()); renderAppGroups(); } });
    }

    function renderAppGroups() {
        const container = document.getElementById('app_area'); container.innerHTML = '';
        config.groupOrder.forEach(appName => {
            const isDefault = DEFAULT_APP_NAMES.includes(appName);
            const row = document.createElement('div'); row.className = 'app-row p-2 border-bottom'; row.dataset.app = appName;
            let selected = isDefault ? (config.appGroups[appName] || []) : (config.customAppGroups.find(g=>g.name===appName)?.targetLBs || []);
            let html = '<h6>'+appName+'</h6><div class="checkbox-grid">';
            getLBNames().forEach(lb => {
                html += '<div class="form-check form-check-inline"><input class="form-check-input" type="checkbox" value="'+lb+'" '+(selected.includes(lb)?'checked':'')+'><label class="small">'+lb+'</label></div>';
            });
            row.innerHTML = html + '</div>'; container.appendChild(row);
        });
    }

    function getLBNames() { return Array.from(document.querySelectorAll('.lb-n')).map(i => i.value).filter(v=>v); }

    const ruleModal = new bootstrap.Modal(document.getElementById('ruleModal'));
    function openRuleEditor(mode, name) {
        editingMode = mode; editingGroupName = name;
        document.getElementById('ruleModalTitle').innerText = name || "全局规则";
        document.getElementById('rule-list-container').innerHTML = '';
        let rules = mode === 'global' ? config.customGlobalRules : config.customAppGroups.find(g=>g.name===name).rules;
        (rules || []).forEach(r => addRuleRow(r.type, r.value, r.target, r.noResolve));
        ruleModal.show();
    }
    function openGlobalRuleEditor() { openRuleEditor('global', ''); }

    function addRuleRow(type='DOMAIN-SUFFIX', val='', target='DIRECT', noResolve=false) {
        const div = document.createElement('div'); div.className = 'input-group mb-2 rule-row';
        let typeOpts = ALL_RULE_TYPES.map(t => '<option '+(type===t?'selected':'')+'>'+t+'</option>').join('');
        let targetInput = editingMode === 'global' ? '<select class="form-select rule-target">'+BUILT_IN_POLICIES.map(p=>'<option '+(target===p?'selected':'')+'>'+p+'</option>').join('')+'</select>' : '';
        div.innerHTML = '<select class="form-select rule-type">'+typeOpts+'</select><input type="text" class="form-control rule-value" value="'+val+'">'+targetInput+'<input type="checkbox" class="form-check-input ms-2 rule-no-res" '+(noResolve?'checked':'')+'><button class="btn btn-danger btn-sm" onclick="this.parentElement.remove()">×</button>';
        document.getElementById('rule-list-container').appendChild(div);
    }

    function saveRulesFromModal() {
        const newRules = Array.from(document.querySelectorAll('.rule-row')).map(row => ({
            type: row.querySelector('.rule-type').value,
            value: row.querySelector('.rule-value').value,
            target: row.querySelector('.rule-target')?.value || '',
            noResolve: row.querySelector('.rule-no-res').checked
        }));
        if(editingMode === 'global') config.customGlobalRules = newRules;
        else config.customAppGroups.find(g=>g.name===editingGroupName).rules = newRules;
        ruleModal.hide();
    }

    async function save() {
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({ name: el.querySelector('.lb-n').value, regex: el.querySelector('.lb-r').value }));
        const appGroups = {};
        document.querySelectorAll('.app-row').forEach(row => {
            const name = row.dataset.app; const sels = Array.from(row.querySelectorAll('input:checked')).map(i=>i.value);
            if(DEFAULT_APP_NAMES.includes(name)) appGroups[name] = sels;
            else config.customAppGroups.find(g=>g.name===name).targetLBs = sels;
        });
        const newConfig = {
            ...config, lbGroups, appGroups, 
            enableOverwrite: document.getElementById('enable_overwrite').checked,
            healthCheckInterval: document.getElementById('interval').value,
            dnsSettings: { ...config.dnsSettings, enable: document.getElementById('dns_enable').checked, 'enhanced-mode': document.getElementById('dns_enhanced').value, nameserver: document.getElementById('dns_ns').value.split('\\n').filter(v=>v) }
        };
        await fetch('/?action=saveConfig', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash, newConfig }) });
        alert("已保存");
    }

    async function loadStats() {
        const res = await fetch('/?action=getStats', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ authHash: authTokenHash }) }).then(r=>r.json());
        if(res.success) {
            let html = '<h5>总请求: '+res.total+'</h5><table class="table table-sm"><thead><tr><th>UA</th><th>次数</th></tr></thead><tbody>';
            res.data.forEach(i => html += '<tr><td class="small">'+i.label+'</td><td>'+i.count+'</td></tr>');
            document.getElementById('stats_tables').innerHTML = html + '</tbody></table>';
        }
    }
    function doLogout() { sessionStorage.removeItem('authHash'); location.reload(); }
    function addNewCustomGroup() { 
        let n = prompt("名称"); 
        if(n) { config.groupOrder.push(n); config.customAppGroups.push({name:n, rules:[], targetLBs:[]}); renderSortableGroups(); renderAppGroups(); } 
    }
    function deleteGroup(n) { config.groupOrder = config.groupOrder.filter(i=>i!==n); renderSortableGroups(); renderAppGroups(); }
</script>
</body>
</html>`;
}