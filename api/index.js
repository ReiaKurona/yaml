const yaml = require('js-yaml');
const axios = require('axios');
const { kv } = require('@vercel/kv');

// 管理员登录密码（请在 Vercel 环境变量中设置 ADMIN_PASSWORD，或直接修改下面这行）
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin888"; 

// 默认配置（当数据库为空时使用）
const DEFAULT_CONFIG = {
    lbGroups: [
        { name: "香港", regex: "HK|hong|🇭🇰" },
        { name: "日本", regex: "JP|japan|🇯🇵" },
        { name: "加拿大", regex: "CA|canada|🇨🇦" }
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
    // A. 管理后台逻辑 (保存配置)
    // -----------------------------------------------------------------------
    if (req.method === 'POST' && action === 'saveConfig') {
        const { auth, newConfig } = req.body;
        if (auth !== ADMIN_PASSWORD) return res.status(403).json({ msg: "密码错误" });
        
        await kv.set('global_config', newConfig);
        return res.json({ msg: "配置已全局保存，用户订阅将立即生效" });
    }

    // -----------------------------------------------------------------------
    // B. 管理后台逻辑 (展示界面)
    // -----------------------------------------------------------------------
    if (!subUrl) {
        const savedConfig = await kv.get('global_config');
        const currentConfig = savedConfig || DEFAULT_CONFIG;
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        return res.send(renderAdminPage(currentConfig));
    }

    // -----------------------------------------------------------------------
    // C. 订阅覆写逻辑 (用户访问)
    // -----------------------------------------------------------------------
    try {
        // 从数据库读取全局配置
        const savedConfig = await kv.get('global_config');
        const userConfig = savedConfig || DEFAULT_CONFIG;

        const isClash = /clash|mihomo|stash/i.test(ua);
        const response = await axios.get(subUrl, {
            headers: { 'User-Agent': isClash ? 'ClashMeta' : ua },
            responseType: 'text',
            timeout: 10000
        });

        // 非 Clash 转发
        if (!isClash) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            if (response.headers['subscription-userinfo']) res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
            return res.send(response.data);
        }

        // Clash 修改逻辑
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

// 后台 HTML 模板
function renderAdminPage(config) {
    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextReia 全局后台</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>body{background:#f4f7f6;padding:20px} .card{margin-bottom:20px}</style>
</head>
<body>
<div class="container" style="max-width:800px">
    <h3 class="mb-4">🛠️ 订阅全局管理后台</h3>
    
    <div class="card">
        <div class="card-header bg-dark text-white">身份验证</div>
        <div class="card-body">
            <input type="password" id="admin_pwd" class="form-control" placeholder="输入管理员密码">
        </div>
    </div>

    <div class="card">
        <div class="card-header">负载均衡组设置 (Regex)</div>
        <div class="card-body" id="lb_area"></div>
        <div class="card-footer"><button class="btn btn-sm btn-secondary" onclick="addLB()">+ 增加地区</button></div>
    </div>

    <div class="card">
        <div class="card-header">未匹配节点设置</div>
        <div class="card-body">
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="unmatched" ${config.includeUnmatched ? 'checked' : ''}>
                <label>将未匹配节点放入 ReiaNEXT</label>
            </div>
        </div>
    </div>

    <button class="btn btn-primary w-100 p-3" onclick="save()">保存全局设置</button>
    <p class="text-muted mt-3 small">* 保存后，所有使用 <code>?url=...</code> 的用户将自动应用新规则，无需更改链接。</p>
</div>

<script>
    let currentConfig = ${JSON.stringify(config)};
    function addLB(val = {name:'', regex:''}) {
        const div = document.createElement('div');
        div.className = 'input-group mb-2';
        div.innerHTML = \`<input type="text" class="form-control lb-n" placeholder="地区" value="\${val.name}">
                          <input type="text" class="form-control lb-r" placeholder="正则" value="\${val.regex}">
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
            appGroups: currentConfig.appGroups,
            includeUnmatched: document.getElementById('unmatched').checked
        };
        const auth = document.getElementById('admin_pwd').value;
        const resp = await fetch('/?action=saveConfig', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ auth, newConfig })
        });
        const res = await resp.json();
        alert(res.msg);
    }
</script>
</body>
</html>`;
}
