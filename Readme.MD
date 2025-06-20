# Pek.WAF

基于DH框架的Kestrel Web 服务器的基本 WAF（Web Application Firewall）库，提供灵活的请求过滤和安全防护功能。

## 特性

- 🛡️ **灵活的规则配置**：支持多种操作符和逻辑组合
- 🚀 **高性能**：基于表达式树的规则编译，运行时性能优异
- 🔧 **易于集成**：简单的扩展方法，快速集成到现有项目
- 📝 **自动配置**：当配置不存在时自动生成默认安全规则
- 🎯 **多种过滤条件**：支持路径、User-Agent、IP地理位置等多维度过滤

## 快速开始

### 1. 安装

```bash
dotnet add package Pek.WAF
```

### 2. 配置服务

在 `Program.cs` 或 `Startup.cs` 中添加 WAF 服务：

```csharp
using Pek.WAF.Extensions;

// 添加 WAF 服务
builder.Services.AddWebFirewall(builder.Configuration);

// 使用 WAF 中间件
app.UseWebFirewall();
```

### 3. 配置规则

#### 使用 DH/Pek 框架时的配置文件位置

如果您在项目中使用了 `ConfigFileHelper.SetConfig(builder.Configuration)` 方法，系统会按以下优先级顺序查找 `Settings` 目录：

1. `{应用程序目录}/Settings/`
2. `{应用程序目录}/Data/Settings/`
3. `{应用程序目录}/../Settings/`
4. `{应用程序目录}/bin/Settings/`

请将包含 WAF 规则的 JSON 配置文件（如 `Ruleset.json` 或在 `appsettings.json` 中包含规则配置）放置在上述任一 `Settings` 目录中。系统会自动加载该目录下的所有 `*.json` 文件。

#### 标准配置方式

在 `appsettings.json` 中添加规则配置：

```json
{
  "Ruleset": {
    "Operator": "OrElse",
    "Rules": [
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".php"]
      },
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".env"]
      },
      {
        "MemberName": "Path",
        "Operator": "EndsWith",
        "Inputs": [".git"]
      }
      // 更多规则示例（可根据需要启用）：
      // {
      //   "MemberName": "UserAgent",
      //   "Operator": "IsMatch",
      //   "TargetValue": "^(curl|java|python)"
      // },
      // {
      //   "MemberName": "IpCountry",
      //   "Operator": "IsInInput",
      //   "Inputs": ["CN", "RU"]
      // }
    ]
  }
}
```

## 配置说明

### 基本结构

```json
{
  "Ruleset": {
    "Operator": "OrElse",  // 逻辑操作符
    "Rules": [             // 规则数组
      // 具体规则
    ]
  }
}
```

### 支持的操作符

#### 字符串操作符
- `EndsWith`: 检查字符串是否以指定值结尾
- `StartsWith`: 检查字符串是否以指定值开头
- `Contains`: 检查字符串是否包含指定值
- `Equals`: 检查字符串是否等于指定值
- `IsMatch`: 使用正则表达式匹配

#### 集合操作符
- `IsInInput`: 检查值是否在指定的输入列表中

#### 逻辑操作符
- `OrElse`: 逻辑或（任一规则匹配即触发）
- `AndAlso`: 逻辑与（所有规则都匹配才触发）

### 可用的请求属性

- `Path`: 请求路径
- `Method`: HTTP 方法
- `UserAgent`: 用户代理字符串
- `IpAddress`: 客户端 IP 地址
- `IpCountry`: IP 地理位置国家代码
- `Headers`: 请求头
- `QueryString`: 查询字符串
- `ContentType`: 内容类型

## 高级配置示例

### 1. User-Agent 检测

```json
{
  "MemberName": "UserAgent",
  "Operator": "IsMatch",
  "TargetValue": "^(curl|java|python)"
}
```

### 2. IP 地理位置过滤

```json
{
  "MemberName": "IpCountry",
  "Operator": "IsInInput",
  "Inputs": ["CN", "RU"]
}
```

### 3. HTTP 方法限制

```json
{
  "MemberName": "Method",
  "Operator": "IsInInput",
  "Inputs": ["POST", "PUT", "DELETE"]
}
```

### 4. 管理路径保护

```json
{
  "MemberName": "Path",
  "Operator": "StartsWith",
  "Inputs": ["/admin", "/wp-admin", "/phpmyadmin"]
}
```

### 5. 白名单规则（使用 Negate）

```json
{
  "MemberName": "Path",
  "Operator": "EndsWith",
  "Inputs": [".html", ".css", ".js", ".png", ".jpg"],
  "Negate": true
}
```

## 规则属性说明

- `MemberName`: 要检查的请求属性名称
- `Operator`: 使用的操作符
- `TargetValue`: 目标值（用于正则表达式等）
- `Inputs`: 输入值列表（用于集合操作）
- `Negate`: 是否取反结果（可选，默认为 false）
- `Rules`: 嵌套规则数组（用于复杂逻辑组合）

## 自动配置

如果没有在 `appsettings.json` 中配置 `Ruleset` 节点，WAF 会自动使用默认配置，包含以下安全规则：

- 阻止访问 `.php` 文件
- 阻止访问 `.env` 文件
- 阻止访问 `.git` 相关文件

## 最佳实践

1. **性能优化**: 将最常匹配的规则放在前面
2. **安全考虑**: 定期更新规则以应对新的威胁
3. **测试**: 在生产环境部署前充分测试规则
4. **监控**: 记录被阻止的请求以分析攻击模式
5. **白名单**: 考虑使用 `Negate` 属性创建白名单规则

## 许可证

本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目。