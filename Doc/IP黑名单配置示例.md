# IP黑名单配置与日志查看指南

## 项目架构说明

### 核心组件

1. **WAFMiddleware**: ASP.NET Core 中间件，拦截所有 HTTP 请求
2. **MRE (Mini Rules Engine)**: 规则引擎，将 JSON 规则编译为高性能的表达式树
3. **WebRequest**: 封装请求信息，提供多种 IP 检查方法
4. **Rule**: 规则定义，支持复杂的逻辑组合

### 工作流程

```
HTTP请求 → WAFMiddleware → 创建 WebRequest 对象 
         → 执行编译后的规则委托 (compiledRule)
         → 返回 true (拦截/403) 或 false (放行)
```

## IP黑名单配置方式

### 方式一：使用 IsInIpList 方法（推荐）

支持精确匹配、CIDR、通配符等多种格式，配置灵活：

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "IsInIpList",
        "Inputs": ["192.168.1.100, 10.0.0.0/8, 172.16.*.*"]
      }
    ]
  }
}
```

**支持的IP格式：**
- 精确匹配: `192.168.1.100`
- CIDR格式: `192.168.1.0/24`, `10.0.0.0/8`
- 通配符: `192.168.*.*`, `10.0.1.*`
- 混合使用: `192.168.1.1, 192.168.1.2; 10.0.0.0/8; 172.16.*.*`

### 方式二：使用 InSubnet 方法

检查IP是否在指定子网内：

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "InSubnet",
        "Inputs": ["192.168.1.0", 24]
      },
      {
        "MemberName": "RemoteIp",
        "Operator": "InSubnet",
        "Inputs": ["10.0.0.0", 8]
      }
    ]
  }
}
```

### 方式三：使用 IpInFile 方法

从文件加载黑名单（支持缓存）：

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "IpInFile",
        "Inputs": ["blacklist.txt"]
      }
    ]
  }
}
```

**blacklist.txt 文件格式：**
```
192.168.1.100
192.168.1.101
10.0.0.5
```

### 方式四：精确IP匹配

使用 Equal 操作符：

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "Equal",
        "TargetValue": "192.168.1.100"
      },
      {
        "MemberName": "RemoteIp",
        "Operator": "Equal",
        "TargetValue": "10.0.0.5"
      }
    ]
  }
}
```

### 方式五：IP白名单（反向逻辑）

使用 `IsNotInIpList` 或 `Negate` 属性：

```json
{
  "Ruleset": {
    "MemberName": "RemoteIp",
    "Operator": "IsNotInIpList",
    "Inputs": ["192.168.1.0/24, 10.0.0.1"]
  }
}
```

或者：

```json
{
  "Ruleset": {
    "MemberName": "RemoteIp",
    "Operator": "IsInIpList",
    "Inputs": ["192.168.1.0/24, 10.0.0.1"],
    "Negate": true
  }
}
```

## 复杂规则组合示例

### 示例1：IP黑名单 + 路径保护

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "IsInIpList",
        "Inputs": ["192.168.1.100, 10.0.0.0/8"]
      },
      {
        "MemberName": "Path",
        "Operator": "StartsWith",
        "Inputs": ["/admin"]
      },
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".php"]
      }
    ]
  }
}
```

### 示例2：特定路径的IP白名单

只允许特定IP访问管理后台：

```json
{
  "Ruleset": {
    "Operator": "AndAlso",
    "Rules": [
      {
        "MemberName": "Path",
        "Operator": "StartsWith",
        "Inputs": ["/admin"]
      },
      {
        "MemberName": "RemoteIp",
        "Operator": "IsNotInIpList",
        "Inputs": ["192.168.1.1, 192.168.1.2, 10.0.0.100"]
      }
    ]
  }
}
```

### 示例3：多层嵌套规则

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "Operator": "AndAlso",
        "Rules": [
          {
            "MemberName": "RemoteIp",
            "Operator": "IsInIpList",
            "Inputs": ["10.0.0.0/8"]
          },
          {
            "MemberName": "UserAgent",
            "Operator": "IsMatch",
            "TargetValue": "(?i)(bot|crawler|spider)"
          }
        ]
      },
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".php", ".asp", ".jsp"]
      }
    ]
  }
}
```

## 日志输出说明

### 日志控制机制

日志输出支持**两种控制方式**（满足任一条件即输出详细日志）：

#### 方式一：通过 PekSysSetting 配置（✅ 推荐）

在 `appsettings.json` 中配置：

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true
  }
}
```

**优势：**
- ✅ 无需修改日志级别，不影响其他模块的日志输出
- ✅ 可以在生产环境临时开启调试，无需重启应用
- ✅ 配置支持热重载，修改后立即生效
- ✅ 只影响 WAF 相关的详细日志，精准控制
- ✅ 适合生产环境排查问题

#### 方式二：通过日志级别控制

设置日志级别为 `Debug`：

```csharp
// Program.cs
using NewLife.Log;

XTrace.Log.Level = LogLevel.Debug;
```

或在 `appsettings.json` 中：

```json
{
  "NewLife": {
    "LogLevel": "Debug"
  }
}
```

**特点：**
- 会影响所有使用 NewLife.Log 的模块
- 适合开发环境全局调试

### 日志级别

已添加的日志输出分为两个级别：

#### 1. Debug 级别（详细调试日志）

**触发条件（满足任一）：**
- `PekSysSetting.Current.AllowRequestParams = true` （推荐）
- 或 日志级别设置为 `Debug`

**日志内容：**

- **请求评估日志**: 每个请求都会记录
  ```
  [WAFMiddleware.Invoke]:评估请求 - IP:192.168.1.100, Path:/api/test, Method:GET
  ```

- **子网检查日志**: 记录 InSubnet 方法的调用和结果
  ```
  [WebRequest.InSubnet]:子网检查 - RemoteIP:192.168.1.100, 网络:192.168.1.0/24, 匹配:true
  ```

- **IP文件加载日志**: 第一次加载文件时记录
  ```
  [WebRequest.IpInFile]:加载IP文件 - 文件:blacklist.txt, IP数量:150
  ```

- **IP文件检查日志**: 每次检查都记录
  ```
  [WebRequest.IpInFile]:IP文件检查 - RemoteIP:192.168.1.100, 文件:blacklist.txt, 匹配:true
  ```

- **IP列表解析日志**: 第一次解析时记录
  ```
  [WebRequest.IsInIpList]:解析IP列表 - 规则数量:3, 原始列表:192.168.1.0/24, 10.0.0.1
  ```

- **IP匹配成功日志**: 命中黑名单时记录
  ```
  [WebRequest.IsInIpList]:IP匹配成功 - RemoteIP:192.168.1.100, 规则类型:Exact, 规则值:192.168.1.100
  ```

- **IP不在列表日志**: 未命中黑名单时记录
  ```
  [WebRequest.IsInIpList]:IP不在列表 - RemoteIP:192.168.1.200, 已检查规则数:5
  ```

#### 2. Warn/Info 级别（生产环境）

**触发条件：** 始终输出（无需配置）

**日志内容：**

- **拦截请求日志**: 请求被拦截时记录详细信息
  ```
  [WAFMiddleware.Invoke]:拦截请求 - IP:192.168.1.100, Path:/admin/login, Method:POST, UserAgent:Mozilla/5.0...
  ```

- **规则更新日志**: 规则配置变更时记录
  ```
  [WAFMiddleware.UpdateCompiledRule]:规则已更新 - Operator: OrElse, Rules: 3
  ```

### 配置日志输出

#### 推荐配置（生产环境）

在 `appsettings.json` 中：

```json
{
  "PekSysSetting": {
    "AllowRequestParams": false  // 默认关闭，需要时临时开启
  },
  "NewLife": {
    "LogLevel": "Info"  // 生产环境使用 Info 级别
  }
}
```

**需要调试时，只需临时修改：**

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true  // 开启详细日志
  }
}
```

#### 开发环境配置

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true  // 或者通过日志级别控制
  },
  "NewLife": {
    "LogLevel": "Debug"  // 开发环境可以用 Debug
  }
}
```

## 测试验证步骤

### 1. 配置IP黑名单

创建 `appsettings.json` 或 `Settings/Ruleset.json`：

```json
{
  "Ruleset": {
    "MemberName": "RemoteIp",
    "Operator": "IsInIpList",
    "Inputs": ["127.0.0.1, 192.168.1.100"]
  }
}
```

### 2. 启用详细日志

**方式一（推荐）：** 使用 PekSysSetting 配置

在 `appsettings.json` 中添加：

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true
  }
}
```

**方式二：** 设置日志级别

```csharp
// Program.cs
using NewLife.Log;

XTrace.Log.Level = LogLevel.Debug;
```

### 3. 发送测试请求

```bash
# 被拦截的IP
curl http://localhost:5000/api/test
# 应该返回 403 Forbidden

# 正常IP
curl http://localhost:5000/api/test --interface 192.168.1.2
# 应该正常返回
```

### 4. 查看日志输出

在控制台或日志文件中查看：

```
[DEBUG] [WebRequest.IsInIpList]:解析IP列表 - 规则数量:2, 原始列表:127.0.0.1, 192.168.1.100
[DEBUG] [WAFMiddleware.Invoke]:评估请求 - IP:127.0.0.1, Path:/api/test, Method:GET
[DEBUG] [WebRequest.IsInIpList]:IP匹配成功 - RemoteIP:127.0.0.1, 规则类型:Exact, 规则值:127.0.0.1
[WARN]  [WAFMiddleware.Invoke]:拦截请求 - IP:127.0.0.1, Path:/api/test, Method:GET, UserAgent:curl/7.68.0
```

## 性能说明

1. **规则编译**: 规则首次加载时编译为表达式树，后续执行性能极高
2. **IP列表缓存**: 解析后的IP规则缓存5分钟，避免重复解析
3. **文件缓存**: IP黑名单文件缓存15分钟，减少磁盘IO
4. **Debug日志**: 仅在 Debug 级别输出详细日志，生产环境无性能影响

## 常见问题

### Q: 如何知道IP是否被拦截？

A: 查看 Warn 级别日志，被拦截的请求会输出详细信息。无需任何配置，默认就会记录。

### Q: 为什么看不到 Debug 日志？

A: 确保满足以下任一条件：
- 在 `appsettings.json` 中设置 `PekSysSetting.AllowRequestParams = true`（推荐）
- 或者设置日志级别：`XTrace.Log.Level = LogLevel.Debug;`

### Q: 生产环境如何临时开启调试？

A: 推荐使用 `PekSysSetting.AllowRequestParams` 配置：

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true  // 修改此处即可，支持热重载
  }
}
```

这种方式不会影响其他模块的日志输出。

### Q: AllowRequestParams 和日志级别的区别？

A: 
- **AllowRequestParams**: 只控制 WAF 相关的详细日志，精准控制，适合生产环境
- **LogLevel = Debug**: 影响所有使用 NewLife.Log 的模块，日志量大，适合开发环境

### Q: IP列表支持域名吗？

A: 不支持，只支持IP地址、CIDR、通配符格式。

### Q: 如何动态更新黑名单？

A: 修改配置文件后会自动重新加载（`reloadOnChange: true`），或者修改IP文件后15分钟内会刷新缓存。

### Q: 可以同时使用多种IP检查方法吗？

A: 可以，使用 OrElse 或 AndAlso 组合多个规则。

## 最佳实践

1. **生产环境**: 
   - 日志级别使用 `Info` 或 `Warn`
   - 默认关闭 `AllowRequestParams`
   - 需要调试时临时开启 `AllowRequestParams`
   
2. **开发环境**: 
   - 可以直接开启 `AllowRequestParams` 或使用 `Debug` 日志级别
   - 查看详细的规则匹配过程
   
3. **大量IP**: 使用 `IpInFile` 从文件加载，利用缓存机制

4. **性能优先**: 优先使用 `IsInIpList`，支持多种格式且性能优异

5. **规则测试**: 先在测试环境验证规则，避免误拦截

6. **日志控制**: 使用 `AllowRequestParams` 而非日志级别，避免影响其他模块

## 示例项目配置

完整的 `appsettings.json` 配置示例：

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "NewLife": {
    "LogLevel": "Info",
    "LogPath": "Logs"
  },
  "PekSysSetting": {
    "AllowRequestParams": false
  },
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "RemoteIp",
        "Operator": "IsInIpList",
        "Inputs": ["192.168.1.100, 10.0.0.0/8, 172.16.*.*"]
      },
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".php", ".asp", ".env"]
      },
      {
        "MemberName": "UserAgent",
        "Operator": "IsMatch",
        "TargetValue": "(?i)(bot|crawler|scanner)"
      }
    ]
  }
}
```

**生产环境调试时，只需修改：**

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true  // 临时开启，排查完问题后改回 false
  }
}
```
