const yaml = require('js-yaml');
const axios = require('axios');

module.exports = async (req, res) => {
    // 获取参数
    const subUrl = req.query.url;
    const ua = req.headers['user-agent'] || '';

    if (!subUrl) {
        return res.status(400).send('使用方法: https://你的域名/?url=原始订阅链接');
    }

    try {
        // 1. 客户端检测 (Clash / Mihomo / Stash)
        const isClash = /clash|mihomo|stash/i.test(ua);

        // 2. 获取原始订阅
        // 转发原始 UA 以确保面板返回正确格式
        const response = await axios.get(subUrl, {
            headers: { 'User-Agent': isClash ? 'ClashMeta' : ua },
            responseType: 'text',
            timeout: 10000
        });

        // 3. 如果是非 Clash 客户端，直接原样返回
        if (!isClash) {
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            if (response.headers['subscription-userinfo']) {
                res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
            }
            return res.send(response.data);
        }

        // 4. Clash 逻辑：解析并修改 YAML
        let config = yaml.load(response.data);
        if (!config || !config.proxies) {
            return res.status(500).send('订阅内容不包含有效代理节点');
        }

        const allProxyNames = config.proxies.map(p => p.name);

        // 匹配函数
        const getNodes = (reg) => {
            const matched = allProxyNames.filter(name => reg.test(name));
            return matched.length > 0 ? matched : ["DIRECT"];
        };

        const hkNodes = getNodes(/HK|hong|🇭🇰/i);
        const jpNodes = getNodes(/JP|japan|🇯🇵/i);
        const caNodes = getNodes(/CA|canada|🇨🇦/i);

        // 5. 严格按照你要求的模板重新定义策略组
        const MY_GROUPS = [
            // 主选择组
            { name: "ReiaNEXT", type: "select", proxies: ["♻️ 自动选择", "🇭🇰 香港 自动负载", "🇯🇵 日本 自动负载", "🇨🇦 加拿大 自动负载", "🚫 故障转移"] },
            
            // 应用分流组
            { name: "Sora&ChatGPT", type: "select", proxies: ["🇯🇵 日本 自动负载", "🇨🇦 加拿大 自动负载", "🚀 节点选择"] },
            { name: "ABEMA", type: "select", proxies: ["🇯🇵 日本 自动负载", "🚀 节点选择"] },
            { name: "赛马娘PrettyDerby", type: "select", proxies: ["🇯🇵 日本 自动负载", "🚀 节点选择"] },
            { name: "PJSK-JP", type: "select", proxies: ["🇯🇵 日本 自动负载", "🚀 节点选择"] },
            { name: "Claude", type: "select", proxies: ["🇯🇵 日本 自动负载", "🇨🇦 加拿大 自动负载", "🚀 节点选择"] },
            
            // 自动测速与故障转移 (包含所有节点)
            { name: "♻️ 自动选择", type: "url-test", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 86400 },
            { name: "🚫 故障转移", type: "fallback", proxies: allProxyNames, url: "http://www.gstatic.com/generate_204", interval: 7200 },
            
            // 负载均衡组 (核心：轮询模式)
            { 
                name: "🇭🇰 香港 自动负载", type: "load-balance", proxies: hkNodes, 
                url: "http://www.gstatic.com/generate_204", interval: 300, strategy: "round-robin" 
            },
            { 
                name: "🇯🇵 日本 自动负载", type: "load-balance", proxies: jpNodes, 
                url: "http://www.gstatic.com/generate_204", interval: 300, strategy: "round-robin" 
            },
            { 
                name: "🇨🇦 加拿大 自动负载", type: "load-balance", proxies: caNodes, 
                url: "http://www.gstatic.com/generate_204", interval: 300, strategy: "round-robin" 
            }
        ];

        // 替换原有的策略组
        config['proxy-groups'] = MY_GROUPS;

        // 6. 返回结果
        res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
        // 转发面板的流量信息
        if (response.headers['subscription-userinfo']) {
            res.setHeader('subscription-userinfo', response.headers['subscription-userinfo']);
        }
        
        // 输出修改后的 YAML
        res.send(yaml.dump(config));

    } catch (err) {
        res.status(500).send(`Error: ${err.message}`);
    }
};
