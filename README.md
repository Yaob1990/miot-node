# miot-node
通过 node 或者网页环境操作小米设备，目前采用云模式，后续会考虑支持局域网模式。

## 基本使用

```ts
import miCloud from "./MiCloud";

const miCloud = new MiCloud()
await miCloud.login("username", "password")
await miCloud
  .miotAction({ did: '', siid: '', aiid: '' })
```

| 方法名 | 说明                      |
| --- |-------------------------|
| login | 登录米家，注意只能是米家 uid，不能是手机号 |
| miotAction | 执行米家设备行为                |
| getDevices | 获取米家设备列表 |

## 感谢以下开源项目
* [merdok/homebridge-miot: Homebridge plugin for devices supporting the Xiaomi miot protocol](https://github.com/merdok/homebridge-miot)
* [PeterWaher/MIoT: Mastering Internet of Things](https://github.com/PeterWaher/MIoT)
* [MiEcosystem/miot-plugin-sdk: MIoT Plugin SDK for Android&iOS(beta)](https://github.com/MiEcosystem/miot-plugin-sdk)
* 
