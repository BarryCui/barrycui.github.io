---
layout: post
title:  阻挡恶意ip对设备发起的请求
categories: [network]
tags: [fortinet]
---
##### 描述
攻击者会向Fortigate防火墙的公网地址发起请求，比如试图与设备建立IPSec VPN连接。
可以使用local-in-policy策略对公网接口进行过滤，拒绝入向的恶意的ip发来的流量。

##### 配置示例

```text
config firewall local-in-policy
    edit 0
        set intf "port2"
        set srcaddr "attackers"
        set dstaddr "all"
        set service "ALL"
        set schedule "always"
    next
end
```

这样就阻挡了attackers组的源ip向port2接口发起的入站流量。