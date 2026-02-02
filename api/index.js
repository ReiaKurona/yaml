const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');

// 管理员登录密码
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "tcs154829"; 

// 默认配置
const DEFAULT_CONFIG = {
    // 1. 负载均衡组定义
    lbGroups: [
        { name: "🇭🇰 香港", regex: "HK|hong|🇭🇰" },
        { name: "🇯🇵 日本", regex: "JP|japan|🇯🇵" },
        { name: "🇨🇦 加拿大", regex: "CA|canada|🇨🇦" }
    ],
    // 2. 应用分流默认指向 (仅包含国旗前缀的名称，脚本会自动补全 " 自动负载")
    appGroups: {
        "Sora&ChatGPT": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇹🇼 台湾", "🇸🇬 新加坡"], 
        "ABEMA": ["🇯🇵 日本"],
        "赛马娘PrettyDerby": ["🇯🇵 日本"],
        "PJSK-JP": ["🇯🇵 日本"],
        "Claude": ["🇯🇵 日本", "🇨🇦 加拿大", "🇺🇸 美国", "🇬🇧 英国"]
    },
    // 3. 高级设置
    includeUnmatched: true,
    healthCheckInterval: 120 // 默认 120 秒
};

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || '';

    // -----------------------------------------------------------------------
    // A. 管理后台 API
    // -----------------------------------------------------------------------
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

    // -----------------------------------------------------------------------
    // B. 返回 Web 管理界面
    // -----------------------------------------------------------------------
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        // 合并默认配置，防止新字段(如interval)缺失导致报错
        const currentConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        // 确保 appGroups 存在 (兼容旧数据)
        if (!currentConfig.appGroups) currentConfig.appGroups = DEFAULT_CONFIG.appGroups;
        if (!currentConfig.healthCheckInterval) currentConfig.healthCheckInterval = 120;

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // -----------------------------------------------------------------------
    // C. 订阅生成逻辑
    // -----------------------------------------------------------------------
    try {
        const savedConfig = await kv.get('global_config');
        const userConfig = { ...DEFAULT_CONFIG, ...savedConfig };
        
        // 确保关键参数存在
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

        // 1. 生成负载均衡组
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
                interval: parseInt(intervalTime), // 使用自定义的间隔时间
                strategy: "round-robin"
            });
        });

        const unmatchedNodes = allProxyNames.filter(name => !usedNodeNames.has(name));

        // 2. 生成主选择组 ReiaNEXT
        const MY_GROUPS = [
            { 
                name: "ReiaNEXT", 
                type: "select", 
                proxies: ["♻️ 自动选择", ...lbGroupsOutput.map(g => g.name), "🚫 故障转移", ...(userConfig.includeUnmatched ? unmatchedNodes : [])] 
            }
        ];

        // 3. 生成应用分流组 (根据用户配置)
        // 默认的应用列表，如果用户配置里有就用用户的
        const targetApps = userConfig.appGroups || DEFAULT_CONFIG.appGroups;
        
        Object.keys(targetApps).forEach(appName => {
            // 获取用户勾选的地区列表 (例如 ["🇯🇵 日本", "🇨🇦 加拿大"])
            const selectedRegions = targetApps[appName] || [];
            
            // 转换为实际的组名 (加上 " 自动负载")，并过滤掉当前不存在的组
            const validProxies = selectedRegions
                .map(regionName => `${regionName} 自动负载`)
                .filter(fullName => lbGroupsOutput.find(g => g.name === fullName));

            // 如果没选任何地区，或者选的地区都没节点，默认回退到 ReiaNEXT
            const finalProxies = validProxies.length > 0 ? validProxies : [];
            finalProxies.push("ReiaNEXT");

            MY_GROUPS.push({ 
                name: appName, 
                type: "select", 
                proxies: finalProxies
            });
        });

        // 4. 工具组
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

// -----------------------------------------------------------------------
// 🎨 前端页面
// -----------------------------------------------------------------------
function renderAdminPage(config) {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia 管理后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f4f7f6; padding: 20px; min-height: 100vh; }
        .card { margin-bottom: 20px; border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .card-header { font-weight: 600; background-color: #fff; border-bottom: 1px solid #eee; }
        
        #login-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px);
            z-index: 9999; display: flex; justify-content: center; align-items: center;
        }
        .login-box {
            background: white; padding: 2rem; border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 90%; max-width: 400px; text-align: center;
        }
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
        
        .app-row { padding: 10px 0; border-bottom: 1px dashed #eee; }
        .app-row:last-child { border-bottom: none; }
        .app-label { font-weight: bold; display: block; margin-bottom: 5px; color: #333; }
        .checkbox-grid { display: flex; flex-wrap: wrap; gap: 10px; }
        .region-tag { font-size: 0.9em; cursor: pointer; user-select: none; }
    </style>
</head>
<body>

<div id="login-overlay">
    <div class="login-box">
        <h4 class="mb-4">🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg mb-3 text-center" placeholder="请输入管理密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<div class="container" id="main-app" style="max-width:800px">
    <div class="d-flex justify-content-between align-items-center mb-4 pt-2">
        <h3>🛠️ NextReia 全局后台</h3>
        <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">⚠️ 重置配置</button>
    </div>
    
    <!-- 1. 负载均衡组 -->
    <div class="card">
        <div class="card-header text-primary">1. 负载均衡组 (Regex)</div>
        <div class="card-body">
            <div id="lb_area"></div>
            <button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button>
        </div>
    </div>

    <!-- 2. 分流策略组 -->
    <div class="card">
        <div class="card-header text-success">2. 分流策略组配置 (勾选允许的地区)</div>
        <div class="card-body" id="app_area">
            <!-- JS 自动生成 -->
        </div>
    </div>

    <!-- 3. 高级设置 -->
    <div class="card">
        <div class="card-header text-secondary">3. 高级设置</div>
        <div class="card-body">
            <div class="mb-3 row align-items-center">
                <label class="col-sm-4 col-form-label">健康检查间隔 (秒)</label>
                <div class="col-sm-4">
                    <input type="number" id="interval" class="form-control" value="${config.healthCheckInterval || 120}" min="60">
                </div>
                <div class="col-sm-4 text-muted small">默认 120 秒，过短可能导致闪断</div>
            </div>
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                <label class="form-check-label">将未匹配规则的节点放入 ReiaNEXT</label>
            </div>
        </div>
    </div>

    <button class="btn btn-success w-100 p-3 shadow mb-5" onclick="save()">保存全局设置</button>
</div>

<script>
    let currentConfig = ${JSON.stringify(config)};
    let authToken = ""; 

    // 默认的应用列表 (如果配置里没有，用这个兜底)
    const defaultApps = ["Sora&ChatGPT", "ABEMA", "赛马娘PrettyDerby", "PJSK-JP", "Claude"];

    // === 登录 ===
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
                renderUI(); // 登录成功后渲染界面
            } else {
                msg.innerText = "密码错误";
            }
        } catch (e) { msg.innerText = "网络错误"; }
    }
    document.getElementById('login_pwd').addEventListener('keypress', e => e.key === 'Enter' && doLogin());

    // === UI 渲染 ===
    function renderUI() {
        // 1. 渲染负载组输入框
        const lbContainer = document.getElementById('lb_area');
        lbContainer.innerHTML = '';
        currentConfig.lbGroups.forEach(val => addLB(val));

        // 2. 渲染应用分流选择
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

    function removeLB(btn) {
        btn.parentElement.remove();
        updateAppChoices(); // 删除地区后更新选项
    }

    function renderAppGroups() {
        const container = document.getElementById('app_area');
        container.innerHTML = '';
        
        // 获取当前配置中的 App 列表，如果没有则使用默认
        const apps = Object.keys(currentConfig.appGroups).length > 0 ? Object.keys(currentConfig.appGroups) : defaultApps;
        
        apps.forEach(appName => {
            const row = document.createElement('div');
            row.className = 'app-row';
            row.dataset.app = appName;
            
            // 当前该 App 选中的地区
            const selected = currentConfig.appGroups[appName] || [];
            
            let html = \`<span class="app-label">\${appName}</span><div class="checkbox-grid">\`;
            
            // 动态生成选项：基于当前的 lbGroups
            // 我们需要实时获取输入框里的值，或者先用 config 里的
            const currentLBNames = getLBNamesFromDOM();
            
            currentLBNames.forEach(lbName => {
                const isChecked = selected.includes(lbName) ? 'checked' : '';
                html += \`
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="checkbox" value="\${lbName}" \${isChecked}>
                        <label class="form-check-label region-tag">\${lbName}</label>
                    </div>
                \`;
            });
            
            html += \`</div>\`;
            row.innerHTML = html;
            container.appendChild(row);
        });
    }

    // 辅助：从 DOM 获取当前所有的负载组名称
    function getLBNamesFromDOM() {
        const inputs = document.querySelectorAll('.lb-n');
        const names = [];
        inputs.forEach(input => {
            if(input.value) names.push(input.value);
        });
        // 如果 DOM 还没渲染完，回退到 config
        if(names.length === 0) return currentConfig.lbGroups.map(g => g.name);
        return names;
    }

    // 当用户修改地区名称或增删地区时，实时更新下面的选项
    function updateAppChoices() {
        // 保存当前勾选状态
        const tempState = {};
        document.querySelectorAll('.app-row').forEach(row => {
            const app = row.dataset.app;
            const checked = Array.from(row.querySelectorAll('input:checked')).map(i => i.value);
            tempState[app] = checked;
        });

        // 重新渲染，尝试恢复勾选（如果名字变了可能恢复不了，这是符合逻辑的）
        const container = document.getElementById('app_area');
        container.innerHTML = '';
        const currentLBNames = getLBNamesFromDOM();
        
        Object.keys(tempState).forEach(appName => {
            const row = document.createElement('div');
            row.className = 'app-row';
            row.dataset.app = appName;
            
            let html = \`<span class="app-label">\${appName}</span><div class="checkbox-grid">\`;
            currentLBNames.forEach(lbName => {
                // 简单的恢复逻辑：名字完全匹配
                const isChecked = tempState[appName].includes(lbName) ? 'checked' : '';
                html += \`
                    <div class="form-check form-check-inline">
                        <input class="form-check-input" type="checkbox" value="\${lbName}" \${isChecked}>
                        <label class="form-check-label region-tag">\${lbName}</label>
                    </div>
                \`;
            });
            html += \`</div>\`;
            row.innerHTML = html;
            container.appendChild(row);
        });
    }

    // === 保存逻辑 ===
    async function save() {
        // 1. 收集 LB Groups
        const lbGroups = Array.from(document.querySelectorAll('.lb-item')).map(el => ({
            name: el.querySelector('.lb-n').value,
            regex: el.querySelector('.lb-r').value
        })).filter(i => i.name);

        // 2. 收集 App Groups
        const appGroups = {};
        document.querySelectorAll('.app-row').forEach(row => {
            const app = row.dataset.app;
            const selected = Array.from(row.querySelectorAll('input:checked')).map(i => i.value);
            appGroups[app] = selected;
        });

        const newConfig = {
            lbGroups,
            appGroups,
            includeUnmatched: document.getElementById('unmatched').checked,
            healthCheckInterval: document.getElementById('interval').value || 120
        };
        
        try {
            const resp = await fetch('/?action=saveConfig', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: authToken, newConfig })
            });
            if(resp.status === 403) {
                alert("会话已过期，请刷新页面重新登录");
                location.reload();
            } else {
                const res = await resp.json();
                alert(res.msg);
                // 更新本地 config 防止下次操作数据不同步
                currentConfig = newConfig; 
            }
        } catch(e) { alert("保存失败"); }
    }

    async function resetConfig() {
        if(!confirm("确定要重置所有配置为默认状态吗？")) return;
        try {
            const resp = await fetch('/?action=resetConfig', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: authToken })
            });
            const res = await resp.json();
            alert(res.msg);
            location.reload();
        } catch(e) { alert("重置失败"); }
    }
</script>
</body>
</html>`;
}
