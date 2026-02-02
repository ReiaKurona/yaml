const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');

// 管理员登录密码
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin888"; 

// 1. 修正后的默认配置 (注意：name 加上了国旗，与下方的引用保持一致)
const DEFAULT_CONFIG = {
    lbGroups: [
        { name: "🇭🇰 香港", regex: "HK|hong|🇭🇰|IEPL" },
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
    const { url: subUrl, password, action } = req.query;
    const ua = req.headers['user-agent'] || '';

    // -----------------------------------------------------------------------
    // A. 管理后台逻辑
    // -----------------------------------------------------------------------
    if (req.method === 'POST') {
        const { auth, newConfig } = req.body;
        if (auth !== ADMIN_PASSWORD) return res.status(403).json({ msg: "密码错误" });

        if (action === 'saveConfig') {
            await kv.set('global_config', newConfig);
            return res.json({ msg: "✅ 配置已保存，请在客户端刷新订阅！" });
        }
        
        // 新增：重置功能
        if (action === 'resetConfig') {
            await kv.del('global_config');
            return res.json({ msg: "🔄 已重置为默认配置，请刷新页面查看。" });
        }
    }

    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = savedConfig || DEFAULT_CONFIG;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // -----------------------------------------------------------------------
    // B. 订阅处理逻辑
    // -----------------------------------------------------------------------
    try {
        const savedConfig = await kv.get('global_config');
        // 如果数据库里有配置就用数据库的，否则用默认修复版
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

        // 核心修复：确保生成的组名与引用一致
        userConfig.lbGroups.forEach(group => {
            const regex = new RegExp(group.regex, 'i');
            const matched = allProxyNames.filter(name => {
                const m = regex.test(name);
                if (m) usedNodeNames.add(name);
                return m;
            });

            // 这里的 name 会变成 "🇯🇵 日本 自动负载"
            lbGroupsOutput.push({
                name: `${group.name} 自动负载`, 
                type: "load-balance",
                proxies: matched.length > 0 ? matched : ["DIRECT"], // 防止为空时报错
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

function renderAdminPage(config) {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia 管理后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#f4f7f6;padding:20px} .card{margin-bottom:20px}</style>
</head>
<body>
<div class="container" style="max-width:800px">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h3>🛠️ NextReia 全局后台</h3>
        <button class="btn btn-outline-danger btn-sm" onclick="resetConfig()">⚠️ 重置为默认配置</button>
    </div>
    
    <div class="card">
        <div class="card-header bg-dark text-white">身份验证</div>
        <div class="card-body">
            <input type="password" id="admin_pwd" class="form-control" placeholder="输入管理员密码 (默认 admin888)">
        </div>
    </div>

    <div class="card">
        <div class="card-header">负载均衡组 (名称需包含国旗，如: 🇯🇵 日本)</div>
        <div class="card-body" id="lb_area"></div>
        <div class="card-footer"><button class="btn btn-sm btn-secondary" onclick="addLB()">+ 增加地区</button></div>
    </div>

    <div class="card">
        <div class="card-header">设置</div>
        <div class="card-body">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                <label>将未匹配节点放入 ReiaNEXT</label>
            </div>
        </div>
    </div>

    <button class="btn btn-primary w-100 p-3" onclick="save()">保存全局设置</button>
</div>

<script>
    let currentConfig = ${JSON.stringify(config)};
    
    // 渲染负载组
    function addLB(val = {name:'', regex:''}) {
        const div = document.createElement('div');
        div.className = 'input-group mb-2';
        div.innerHTML = \`<input type="text" class="form-control lb-n" placeholder="名称(如: 🇯🇵 日本)" value="\${val.name}">
                          <input type="text" class="form-control lb-r" placeholder="正则(如: JP|Japan)" value="\${val.regex}">
                          <button class="btn btn-danger" onclick="this.parentElement.remove()">删</button>\`;
        document.getElementById('lb_area').appendChild(div);
    }
    currentConfig.lbGroups.forEach(addLB);

    async function save() {
        const newConfig = {
            lbGroups: Array.from(document.querySelectorAll('.input-group')).map(el => ({
                name: el.querySelector('.lb-n').value,
                regex: el.querySelector('.lb-r').value
            })).filter(i => i.name),
            appGroups: currentConfig.appGroups, // 保持默认的分流组引用
            includeUnmatched: document.getElementById('unmatched').checked
        };
        const auth = document.getElementById('admin_pwd').value;
        const resp = await fetch('/?action=saveConfig', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ auth, newConfig })
        });
        if(resp.status === 403) return alert("密码错误");
        const res = await resp.json();
        alert(res.msg);
    }

    async function resetConfig() {
        if(!confirm("确定要重置所有配置为默认状态吗？这将修复名称不匹配的问题。")) return;
        const auth = document.getElementById('admin_pwd').value;
        const resp = await fetch('/?action=resetConfig', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ auth })
        });
        if(resp.status === 403) return alert("密码错误");
        const res = await resp.json();
        alert(res.msg);
        location.reload();
    }
</script>
</body>
</html>`;
}
