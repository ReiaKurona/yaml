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
        "Sora&ChatGPT": ["🇯🇵 日本 自动负载", "🇨🇦 加拿大 自动负载"],
        "ABEMA": ["🇯🇵 日本 自动负载"],
        "赛马娘PrettyDerby": ["🇯🇵 日本 自动负载"],
        "PJSK-JP": ["🇯🇵 日本 自动负载"],
        "Claude": ["🇯🇵 日本 自动负载", "🇨🇦 加拿大 自动负载"]
    },
    includeUnmatched: true
};

module.exports = async (req, res) => {
    const { url: subUrl, action } = req.query;
    const ua = req.headers['user-agent'] || '';

    // -----------------------------------------------------------------------
    // A. 管理后台 API 接口 (处理 POST 请求)
    // -----------------------------------------------------------------------
    if (req.method === 'POST') {
        const { auth, newConfig } = req.body;

        // 1. 纯密码验证接口 (用于登录阶段)
        if (action === 'login') {
            if (auth === ADMIN_PASSWORD) return res.json({ success: true });
            return res.status(403).json({ success: false, msg: "密码错误" });
        }

        // 验证密码 (保存和重置都需要)
        if (auth !== ADMIN_PASSWORD) return res.status(403).json({ msg: "会话失效或密码错误" });

        // 2. 保存配置接口
        if (action === 'saveConfig') {
            await kv.set('global_config', newConfig);
            return res.json({ msg: "✅ 配置已全局保存！" });
        }
        
        // 3. 重置配置接口
        if (action === 'resetConfig') {
            await kv.del('global_config');
            return res.json({ msg: "🔄 已重置为默认配置。" });
        }
    }

    // -----------------------------------------------------------------------
    // B. 返回 Web 管理界面 (如果没有 url 参数)
    // -----------------------------------------------------------------------
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = savedConfig || DEFAULT_CONFIG;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // -----------------------------------------------------------------------
    // C. 订阅转换核心逻辑
    // -----------------------------------------------------------------------
    try {
        const savedConfig = await kv.get('global_config');
        const userConfig = savedConfig || DEFAULT_CONFIG;

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
                interval: 120,
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

        Object.keys(userConfig.appGroups).forEach(appName => {
            MY_GROUPS.push({ name: appName, type: "select", proxies: [...userConfig.appGroups[appName], "ReiaNEXT"] });
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

// -----------------------------------------------------------------------
// 🎨 前端页面 (包含登录遮罩逻辑)
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
        .card-header { font-weight: 600; }
        
        /* 登录遮罩层样式 */
        #login-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(15px); /* 毛玻璃核心代码 */
            -webkit-backdrop-filter: blur(15px);
            z-index: 9999;
            display: flex; justify-content: center; align-items: center;
        }
        .login-box {
            background: white; padding: 2rem; border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 90%; max-width: 400px;
            text-align: center;
        }
        /* 主内容模糊 (未登录时) */
        #main-app { filter: blur(8px); transition: filter 0.3s; pointer-events: none; }
        #main-app.active { filter: blur(0); pointer-events: auto; }
    </style>
</head>
<body>

<!-- 🔒 登录遮罩层 -->
<div id="login-overlay">
    <div class="login-box">
        <h4 class="mb-4">🔒 管理员验证</h4>
        <input type="password" id="login_pwd" class="form-control form-control-lg mb-3 text-center" placeholder="请输入管理密码">
        <button class="btn btn-primary btn-lg w-100" onclick="doLogin()">进入后台</button>
        <div id="login-msg" class="text-danger mt-2 small"></div>
    </div>
</div>

<!-- 🎛️ 主界面 (初始模糊) -->
<div class="container" id="main-app" style="max-width:800px">
    <div class="d-flex justify-content-between align-items-center mb-4 pt-2">
        <h3>🛠️ NextReia 全局后台</h3>
        <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">⚠️ 重置配置</button>
    </div>
    
    <div class="card">
        <div class="card-header bg-primary text-white">负载均衡组 (Regex)</div>
        <div class="card-body">
            <div id="lb_area"></div>
            <button class="btn btn-sm btn-outline-primary mt-2" onclick="addLB()">+ 增加地区</button>
        </div>
    </div>

    <div class="card">
        <div class="card-header bg-secondary text-white">高级设置</div>
        <div class="card-body">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                <label>将未匹配节点放入 ReiaNEXT</label>
            </div>
        </div>
    </div>

    <button class="btn btn-success w-100 p-3 shadow" onclick="save()">保存全局设置</button>
</div>

<script>
    let currentConfig = ${JSON.stringify(config)};
    let authToken = ""; // 登录后存储密码用于API请求

    // === 1. 登录逻辑 ===
    async function doLogin() {
        const pwd = document.getElementById('login_pwd').value;
        const btn = document.querySelector('#login-overlay button');
        const msg = document.getElementById('login-msg');

        if(!pwd) return msg.innerText = "密码不能为空";

        btn.disabled = true;
        btn.innerText = "验证中...";

        try {
            const resp = await fetch('/?action=login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: pwd })
            });
            const res = await resp.json();

            if (res.success) {
                // 登录成功
                authToken = pwd; // 暂存密码
                document.getElementById('login-overlay').style.display = 'none'; // 移除遮罩
                document.getElementById('main-app').classList.add('active'); // 移除模糊
            } else {
                msg.innerText = "密码错误，请重试";
                document.getElementById('login_pwd').value = "";
            }
        } catch (e) {
            msg.innerText = "网络错误";
        } finally {
            btn.disabled = false;
            btn.innerText = "进入后台";
        }
    }
    
    // 支持回车登录
    document.getElementById('login_pwd').addEventListener('keypress', function (e) {
        if (e.key === 'Enter') doLogin();
    });

    // === 2. 界面渲染逻辑 ===
    function addLB(val = {name:'', regex:''}) {
        const div = document.createElement('div');
        div.className = 'input-group mb-2';
        div.innerHTML = \`<input type="text" class="form-control lb-n" placeholder="名称(如: 🇯🇵 日本)" value="\${val.name}">
                          <input type="text" class="form-control lb-r" placeholder="正则(如: JP|Japan)" value="\${val.regex}">
                          <button class="btn btn-danger" onclick="this.parentElement.remove()">×</button>\`;
        document.getElementById('lb_area').appendChild(div);
    }
    currentConfig.lbGroups.forEach(addLB);

    // === 3. 保存与重置逻辑 ===
    async function save() {
        const newConfig = {
            lbGroups: Array.from(document.querySelectorAll('.input-group')).map(el => ({
                name: el.querySelector('.lb-n').value,
                regex: el.querySelector('.lb-r').value
            })).filter(i => i.name),
            appGroups: currentConfig.appGroups,
            includeUnmatched: document.getElementById('unmatched').checked
        };
        
        try {
            const resp = await fetch('/?action=saveConfig', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ auth: authToken, newConfig })
            });
            const res = await resp.json();
            if(resp.status === 403) {
                alert("会话已过期，请刷新页面重新登录");
                location.reload();
            } else {
                alert(res.msg);
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
