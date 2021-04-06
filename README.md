# Zerotier Central to DNSPod

把 Zerotier Central 中某网络的所有成员自动添加相应A记录至 DNSPod 管理下的某域名。

## 开发动力

Android 对 mDNS 支持过差...

## 使用说明

Zerotier Central 中设备分配的`Name`栏被用作主机名，因此需要只包含`[a-zA-Z0-9-]{1,63}`的内容。不合规则的名称将被忽略。`Description`栏可以自由发挥。

填好脚本内变量或设定环境变量后，作为定时任务挂载到crontab下即可。1h一次应该够了。

## 限制

一个网络内一个设备只支持一个V4和一个V6。无多地址实现企划（没有思路）

## 实现相关细节

在域名备注栏加入了`ZTC2DNSPOD: ZT-ID`作为管理标识，因此不依赖其它信息即可管理`DNS记录<->ZT设备`映射。

也就是说，允许在 Zerotier Central 内进行`Name`和`assigned IP`的变动，增删设备，都会同步到 DNSPod上。

