const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');

// 管理员登录密码
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "tcs154829"; 

// 默认配置
const DEFAULT_CONFIG = {
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
    includeUnmatched: true,
    healthCheckInterval: 120
};

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || '';

    // A. API 接口
    if (req.method === 'POST') {
        const { auth, newConfig } = req.body;

        if (action === 'login') {
            if (auth === ADMIN_PASSWORD) return res.json({ success: true });
            return res.status(403).json({ success: false, msg: "密码错误" });
        }
        if (auth !== ADMIN_PASSWORD) return res.status(403).json({ msg: "会话失效" });
        if (action === 'saveConfig') {
            await kv.set('global_config', newConfig);
            return res.json({ msg: "✅ 全局配置已保存！" });
        }
        if (action === 'resetConfig') {
            await kv.del('global_config');
            return res.json({ msg: "🔄 已重置为默认配置。" });
        }
    }

    // B. 返回 Web 界面
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        if (!currentConfig.appGroups) currentConfig.appGroups = DEFAULT_CONFIG.appGroups;
        if (!currentConfig.healthCheckInterval) currentConfig.healthCheckInterval = 120;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // C. 订阅生成逻辑
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
//以下为Webui的HTML渲染部分
function renderAdminPage(config) {
    return `
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="auto">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia 管理后台</title>
    <!-- 引入 Bootstrap 5.3 (支持深色模式) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root { --blur-amt: 12px; }
        body { background-color: var(--bs-body-bg); transition: background-color 0.3s; padding: 20px; min-height: 100vh; }
        
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 12px rgba(0,0,0,0.08); transition: all 0.3s ease; }
        [data-bs-theme="dark"] .card { box-shadow: 0 4px 12px rgba(0,0,0,0.4); background-color: #2b3035; }
        .card-header { font-weight: 600; }
        
        /* 登录遮罩层 */
        #login-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(255, 255, 255, 0.4); /* 浅色模式下的半透明白 */
            backdrop-filter: blur(var(--blur-amt)); -webkit-backdrop-filter: blur(var(--blur-amt));
            z-index: 9998; display: flex; justify-content: center; align-items: center;
            transition: all 0.3s;
        }
        /* 深色模式下的遮罩调整 */
        [data-bs-theme="dark"] #login-overlay { background: rgba(0, 0, 0, 0.6); }

        .login-box {
            background: var(--bs-body-bg); padding: 2.5rem; border-radius: 16px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2); width: 90%; max-width: 420px; text-align: center;
            border: 1px solid var(--bs-border-color);
        }

        /* 主内容模糊 */
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        
        /* App 列表样式 */
        .app-row { padding: 12px 0; border-bottom: 1px dashed var(--bs-border-color); }
        .app-row:last-child { border-bottom: none; }
        .app-label { font-weight: bold; display: block; margin-bottom: 8px; color: var(--bs-emphasis-color); }
        .checkbox-grid { display: flex; flex-wrap: wrap; gap: 10px; }
        .region-tag { font-size: 0.9em; cursor: pointer; user-select: none; }

        /* 主题切换按钮位置 (置于所有层级之上) */
        .theme-switcher { position: fixed; top: 20px; right: 20px; z-index: 9999; }
    </style>
    <script>
        // 初始化主题逻辑 (防闪烁)
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
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
                const storedTheme = getStoredTheme();
                if (storedTheme !== 'light' && storedTheme !== 'dark') {
                    setTheme(getPreferredTheme());
                }
            });
            window.addEventListener('DOMContentLoaded', () => {
                const showActiveTheme = (theme, focus = false) => {
                    const themeSwitcher = document.querySelector('#bd-theme');
                    if (!themeSwitcher) return;
                    const activeThemeIcon = document.querySelector('.theme-icon-active');
                    const btnToActive = document.querySelector(\`[data-bs-theme-value="\${theme}"]\`);
                    const iconOfActiveBtn = btnToActive.querySelector('svg').innerHTML;
                    
                    document.querySelectorAll('[data-bs-theme-value]').forEach(element => {
                        element.classList.remove('active');
                        element.setAttribute('aria-pressed', 'false');
                    });
                    btnToActive.classList.add('active');
                    btnToActive.setAttribute('aria-pressed', 'true');
                    activeThemeIcon.innerHTML = iconOfActiveBtn; // 更新显示的图标
                }
                
                document.querySelectorAll('[data-bs-theme-value]').forEach(toggle => {
                    toggle.addEventListener('click', () => {
                        const theme = toggle.getAttribute('data-bs-theme-value');
                        setStoredTheme(theme);
                        setTheme(theme);
                        showActiveTheme(theme, true);
                    });
                });
                showActiveTheme(getPreferredTheme());
            });
        })();
    </script>
</head>
<body>

<!-- 🌓 主题切换下拉菜单 (登录前可用) -->
<div class="dropdown theme-switcher">
    <button class="btn btn-outline-secondary dropdown-toggle d-flex align-items-center" id="bd-theme" type="button" aria-expanded="false" data-bs-toggle="dropdown" aria-label="Toggle theme">
        <svg class="bi me-1 theme-icon-active" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 0 8 1v14zm0 1A8 8 0 1 1 8 0a8 8 0 0 1 0 16z"/></svg>
        <span class="d-none d-lg-block ms-1">主题</span>
    </button>
    <ul class="dropdown-menu dropdown-menu-end shadow" aria-labelledby="bd-theme">
        <li>
            <button type="button" class="dropdown-item d-flex align-items-center" data-bs-theme-value="light">
                <svg class="bi me-2 opacity-50 theme-icon" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm0 1a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM8 0a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 0zm0 13a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-1 0v-2A.5.5 0 0 1 8 13zm8-5a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2a.5.5 0 0 1 .5.5zM3 8a.5.5 0 0 1-.5.5h-2a.5.5 0 0 1 0-1h2A.5.5 0 0 1 3 8zm10.657-5.657a.5.5 0 0 1 0 .707l-1.414 1.415a.5.5 0 1 1-.707-.708l1.414-1.414a.5.5 0 0 1 .707 0zm-9.193 9.193a.5.5 0 0 1 0 .707L3.05 13.657a.5.5 0 0 1-.707-.707l1.414-1.414a.5.5 0 0 1 .707 0zm9.193 2.121a.5.5 0 0 1-.707 0l-1.414-1.414a.5.5 0 0 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .707zM4.464 4.465a.5.5 0 0 1-.707 0L2.343 3.05a.5.5 0 1 1 .707-.707l1.414 1.414a.5.5 0 0 1 0 .708z"/></svg>
                浅色
            </button>
        </li>
        <li>
            <button type="button" class="dropdown-item d-flex align-items-center" data-bs-theme-value="dark">
                <svg class="bi me-2 opacity-50 theme-icon" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 .278a.768.768 0 0 1 .08.858 7.208 7.208 0 0 0-.878 3.46c0 4.021 3.278 7.277 7.318 7.277.527 0 1.04-.055 1.533-.16a.787.787 0 0 1 .81.316.733.733 0 0 1-.031.893A8.349 8.349 0 0 1 8.344 16C3.734 16 0 12.286 0 7.71 0 4.266 2.114 1.312 5.124.06A.752.752 0 0 1 6 .278z"/></svg>
                深色
            </button>
        </li>
        <li><hr class="dropdown-divider"></li>
        <li>
            <button type="button" class="dropdown-item d-flex align-items-center" data-bs-theme-value="auto">
                <svg class="bi me-2 opacity-50 theme-icon" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 0 8 1v14zm0 1A8 8 0 1 1 8 0a8 8 0 0 1 0 16z"/></svg>
                跟随系统
            </button>
        </li>
    </ul>
</div>

<!-- 🔒 登录遮罩 -->
<div id="login-overlay">
    <div class="login-box">
        <h4 class="mb-4">🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg mb-3 text-center" placeholder="请输入管理密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<!-- 🎛️ 主界面 -->
<div class="container" id="main-app" style="max-width:800px">
    <div class="d-flex justify-content-between align-items-center mb-4 pt-2">
        <h3>🛠️ NextReia 全局后台</h3>
        <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">⚠️ 重置配置</button>
    </div>
    
    <!-- 1. 负载均衡组 -->
    <div class="card">
        <div class="card-header text-primary bg-body-tertiary">1. 负载均衡组 (Regex)</div>
        <div class="card-body">
            <div id="lb_area"></div>
            <button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button>
        </div>
    </div>

    <!-- 2. 分流策略组 -->
    <div class="card">
        <div class="card-header text-success bg-body-tertiary">2. 分流策略组配置 (勾选允许的地区)</div>
        <div class="card-body" id="app_area"></div>
    </div>

    <!-- 3. 高级设置 -->
    <div class="card">
        <div class="card-header text-secondary bg-body-tertiary">3. 高级设置</div>
        <div class="card-body">
            <div class="mb-3 row align-items-center">
                <label class="col-sm-4 col-form-label">健康检查间隔 (秒)</label>
                <div class="col-sm-4">
                    <input type="number" id="interval" class="form-control" value="${config.healthCheckInterval || 120}" min="60">
                </div>
                <div class="col-sm-4 text-muted small">默认 120s，建议 ≥60s</div>
            </div>
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                <label class="form-check-label">将未匹配规则的节点放入 ReiaNEXT</label>
            </div>
        </div>
    </div>

    <button class="btn btn-success w-100 p-3 shadow mb-5" onclick="save()">保存全局设置</button>
</div>

<!-- 引入 Bootstrap JS (用于下拉菜单) -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>

<script>
    let currentConfig = ${JSON.stringify(config)};
    let authToken = ""; 
    const defaultApps = ["Sora&ChatGPT", "ABEMA", "赛马娘PrettyDerby", "PJSK-JP", "Claude"];

    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value;
        const msg = document.getElementById('login-msg');
        if(!pwd) return msg.innerText = "密码不能为空";
        try {
            const resp = await fetch('/?action=login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: pwd })
            });
            const res = await resp.json();
            if (res.success) {
                authToken = pwd;
                document.getElementById('login-overlay').style.display = 'none';
                document.getElementById('main-app').classList.add('active');
                renderUI();
            } else { msg.innerText = "密码错误"; }
        } catch (e) { msg.innerText = "网络错误"; }
    }
    document.getElementById('login_pwd').addEventListener('keypress', e => e.key === 'Enter' && doLogin());

    function renderUI() {
        const lbContainer = document.getElementById('lb_area');
        lbContainer.innerHTML = '';
        currentConfig.lbGroups.forEach(val => addLB(val));
        renderAppGroups();
    }

    function addLB(val = {name:'', regex:''}) {
        const div = document.createElement('div');
        div.className = 'input-group mb-2 lb-item';
        div.innerHTML = \`<input type="text" class="form-control lb-n" placeholder="名称(如: 🇯🇵 日本)" value="\${val.name}" oninput="updateAppChoices()">
                          <input type="text" class="form-control lb-r" placeholder="正则(如: JP|Japan)" value="\${val.regex}">
                          <button class="btn btn-danger" onclick="removeLB(this)">×</button>\`;
        document.getElementById('lb_area').appendChild(div);
    }
    function removeLB(btn) { btn.parentElement.remove(); updateAppChoices(); }

    function renderAppGroups() {
        const container = document.getElementById('app_area');
        container.innerHTML = '';
        const apps = Object.keys(currentConfig.appGroups).length > 0 ? Object.keys(currentConfig.appGroups) : defaultApps;
        apps.forEach(appName => {
            const row = document.createElement('div');
            row.className = 'app-row'; row.dataset.app = appName;
            const selected = currentConfig.appGroups[appName] || [];
            let html = \`<span class="app-label">\${appName}</span><div class="checkbox-grid">\`;
            getLBNamesFromDOM().forEach(lbName => {
                const isChecked = selected.includes(lbName) ? 'checked' : '';
                html += \`<div class="form-check form-check-inline">
                        <input class="form-check-input" type="checkbox" value="\${lbName}" \${isChecked}>
                        <label class="form-check-label region-tag">\${lbName}</label></div>\`;
            });
            html += \`</div>\`; row.innerHTML = html; container.appendChild(row);
        });
    }

    function getLBNamesFromDOM() {
        const names = [];
        document.querySelectorAll('.lb-n').forEach(input => { if(input.value) names.push(input.value); });
        return names.length > 0 ? names : currentConfig.lbGroups.map(g => g.name);
    }

    function updateAppChoices() {
        const tempState = {};
        document.querySelectorAll('.app-row').forEach(row => {
            tempState[row.dataset.app] = Array.from(row.querySelectorAll('input:checked')).map(i => i.value);
        });
        const container = document.getElementById('app_area'); container.innerHTML = '';
        const currentLBNames = getLBNamesFromDOM();
        Object.keys(tempState).forEach(appName => {
            const row = document.createElement('div');
            row.className = 'app-row'; row.dataset.app = appName;
            let html = \`<span class="app-label">\${appName}</span><div class="checkbox-grid">\`;
            currentLBNames.forEach(lbName => {
                const isChecked = tempState[appName].includes(lbName) ? 'checked' : '';
                html += \`<div class="form-check form-check-inline">
                        <input class="form-check-input" type="checkbox" value="\${lbName}" \${isChecked}>
                        <label class="form-check-label region-tag">\${lbName}</label></div>\`;
            });
            html += \`</div>\`; row.innerHTML = html; container.appendChild(row);
        });
    }

    async function save() {
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({
            name: el.querySelector('.lb-n').value, regex: el.querySelector('.lb-r').value
        })).filter(i => i.name);
        const appGroups = {};
        document.querySelectorAll('.app-row').forEach(row => {
            appGroups[row.dataset.app] = Array.from(row.querySelectorAll('input:checked')).map(i => i.value);
        });
        const newConfig = {
            lbGroups, appGroups,
            includeUnmatched: document.getElementById('unmatched').checked,
            healthCheckInterval: document.getElementById('interval').value || 120
        };
        try {
            const resp = await fetch('/?action=saveConfig', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: authToken, newConfig })
            });
            if(resp.status === 403) { alert("会话失效"); location.reload(); }
            else { const res = await resp.json(); alert(res.msg); currentConfig = newConfig; }
        } catch(e) { alert("保存失败"); }
    }

    async function resetConfig() {
        if(!confirm("确定重置为默认配置？")) return;
        try {
            const resp = await fetch('/?action=resetConfig', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: authToken })
            });
            const res = await resp.json(); alert(res.msg); location.reload();
        } catch(e) { alert("重置失败"); }
    }
</script>
</body>
</html>`;
}
