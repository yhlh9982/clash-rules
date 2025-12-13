# 简介

本项目生成适用于 [**Clash Premium 内核**](https://github.com/Dreamacro/clash/releases/tag/premium)的规则集（RULE-SET），同时适用于所有使用 Clash Premium 内核的 Clash 图形用户界面（GUI）客户端。使用 GitHub Actions 北京时间每天早上 6:30 自动构建，保证规则最新。

## 说明

本项目规则集（RULE-SET）的数据主要来源于项目 https://github.com/adysec/tracker BitTorrent Tracker 聚合项目

## 规则文件地址及使用方式

### 在线地址（URL）
 
trackers_domain.yaml - tracker 域名地址
https://raw.githubusercontent.com/yhlh9982/clash-rules/master/trackers_domain.yaml

trackers_ip.yaml - tracker IP地址
https://raw.githubusercontent.com/yhlh9982/clash-rules/master/trackers_ip.yaml


### 使用方式

要想使用本项目的规则集，只需要在 Clash 配置文件中添加如下 `rule-providers` 和 `rules`。

#### Rule Providers 配置方式

```yaml
rule-providers:
  trackers-domain:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/yhlh9982/clash-rules/master/trackers_domain.yaml"
    interval: 86400

  trackers-ip:
    type: http
    behavior: classical
    url: "https://raw.githubusercontent.com/yhlh9982/clash-rules/master/trackers_ip.yaml"
    interval: 86400
```

```yaml
rules:
  - RULE-SET,trackers-ip,直连,no-resolve
  - RULE-SET,trackers-domain,直连
```

## 致谢

- [@Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)
- [@adysec/tracker](https://github.com/adysec/tracker)
