# 更新日志

## [未发布] - 2025-10-26

### 新增

#### 日志功能增强

为 WAF 中间件和 IP 检查方法添加了详细的日志输出，帮助开发者调试和监控IP黑名单功能。

**日志控制机制：**

日志输出现在支持两种控制方式（满足任一条件即输出详细日志）：

1. **通过 `PekSysSetting.Current.AllowRequestParams` 配置**（推荐）
   - 当 `AllowRequestParams = true` 时，无论日志级别如何都会输出详细的 Debug 日志
   - 这是生产环境推荐的调试方式，可以临时开启而无需修改日志级别

2. **通过日志级别控制**
   - 当日志级别设置为 `Debug` 或更低时输出详细日志
   - 传统的日志级别控制方式

**新增日志点：**

1. **WAFMiddleware.UpdateCompiledRule**
   - 级别: Info
   - 触发: 规则配置更新时
   - 内容: 记录规则更新信息

2. **WAFMiddleware.Invoke**
   - 级别: Debug
   - 触发: 每个HTTP请求
   - 内容: 记录请求评估过程（IP、路径、方法）
   
   - 级别: Warn
   - 触发: 请求被拦截时
   - 内容: 记录被拦截请求的详细信息（IP、路径、方法、UserAgent）

3. **WebRequest.InSubnet**
   - 级别: Debug
   - 触发: 调用 InSubnet 方法时
   - 内容: 记录子网匹配检查结果

4. **WebRequest.IpInFile**
   - 级别: Debug
   - 触发: 加载IP文件或检查IP时
   - 内容: 记录文件加载和IP匹配结果

5. **WebRequest.IsInIpList**
   - 级别: Debug
   - 触发: 解析IP列表、IP匹配成功或失败时
   - 内容: 记录IP列表解析、匹配过程和结果

### 改进

- 日志输出采用灵活的控制机制：
  - **推荐方式**: 通过 `PekSysSetting.Current.AllowRequestParams` 配置开关
  - **传统方式**: 通过日志级别（Debug）控制
  - **组合使用**: 满足任一条件即输出详细日志（OR 逻辑）

- 日志输出采用分级设计：
  - **Debug 级别**: 详细的调试信息，包括每个请求的评估过程和IP匹配细节
  - **Warn 级别**: 关键告警信息，只记录被拦截的请求

- 日志格式统一：`[类名.方法名]:描述 - 详细参数`

- 性能友好：
  - Debug 日志仅在条件满足时才执行，避免生产环境性能损失
  - 使用局部变量 `allowDetailLog` 缓存判断结果，避免重复计算

### 技术说明

- 使用 `NewLife.Log.XTrace` 日志框架
- 日志控制逻辑：`PekSysSetting.Current.AllowRequestParams || XTrace.Log.Level <= LogLevel.Debug`
- 引入命名空间：`Pek.Configs`（用于访问 `PekSysSetting`）
- 遵循项目编码规范，保留原有代码结构和注释
- 未改变任何业务逻辑，仅添加日志输出

### 使用方法

#### 方式一：使用 PekSysSetting 配置（推荐）

在 `appsettings.json` 中配置：

```json
{
  "PekSysSetting": {
    "AllowRequestParams": true
  }
}
```

这种方式的优势：
- ✅ 无需修改日志级别，不影响其他模块的日志
- ✅ 可以在生产环境临时开启调试
- ✅ 配置热重载，修改后立即生效
- ✅ 只影响 WAF 相关的详细日志

#### 方式二：启用 Debug 日志级别

在 `Program.cs` 中设置：

```csharp
using NewLife.Log;

XTrace.Log.Level = LogLevel.Debug;
```

或在 `appsettings.json` 中配置：

```json
{
  "NewLife": {
    "LogLevel": "Debug"
  }
}
```

#### 查看日志输出

**生产环境（默认）：** 只看到拦截日志

```log
[WARN] [WAFMiddleware.Invoke]:拦截请求 - IP:192.168.1.100, Path:/admin, Method:GET, UserAgent:curl/7.68.0
```

**开启 AllowRequestParams 或 Debug 模式：** 看到详细过程

```log
[DEBUG] [WebRequest.IsInIpList]:解析IP列表 - 规则数量:3, 原始列表:192.168.1.0/24, 10.0.0.1
[DEBUG] [WAFMiddleware.Invoke]:评估请求 - IP:192.168.1.100, Path:/api/test, Method:GET
[DEBUG] [WebRequest.IsInIpList]:IP匹配成功 - RemoteIP:192.168.1.100, 规则类型:Cidr, 规则值:192.168.1.0/24
[WARN]  [WAFMiddleware.Invoke]:拦截请求 - IP:192.168.1.100, Path:/api/test, Method:GET, UserAgent:Mozilla/5.0
```

### 相关文档

- [IP黑名单配置示例](./Doc/IP黑名单配置示例.md)

### 影响范围

- 仅新增日志输出，不影响现有功能
- 无 Breaking Changes
- 向后兼容所有现有配置
