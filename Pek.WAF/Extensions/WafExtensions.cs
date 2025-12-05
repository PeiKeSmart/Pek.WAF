namespace Pek.WAF.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System;

public static class WafExtensions
{
    public static IServiceCollection AddWebFirewall(this IServiceCollection services, IConfiguration configuration)
    {
        var rulesetSection = configuration.GetSection("Ruleset");
        
        // 如果配置中没有Ruleset节点，则创建默认配置文件
        if (!rulesetSection.Exists())
        {
            CreateDefaultConfigFile();
            
            // 重新加载配置以包含新创建的文件
            var configBuilder = new ConfigurationBuilder();
            configBuilder.AddConfiguration(configuration);
            
            // 尝试加载可能的配置文件位置
            var possiblePaths = GetPossibleConfigPaths();
            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    configBuilder.AddJsonFile(path, optional: true, reloadOnChange: true);
                    break;
                }
            }
            
            var newConfig = configBuilder.Build();
            var newRulesetSection = newConfig.GetSection("Ruleset");
            
            if (newRulesetSection.Exists())
            {
                services.Configure<Rule>(newRulesetSection);
            }
            else
            {
                // 如果仍然无法加载，则使用内存中的默认配置
                var defaultRule = CreateDefaultRule();
                services.Configure<Rule>(options =>
                {
                    options.Operator = defaultRule.Operator;
                    options.Rules = defaultRule.Rules;
                    options.MemberName = defaultRule.MemberName;
                    options.TargetValue = defaultRule.TargetValue;
                    options.Inputs = defaultRule.Inputs;
                    options.Negate = defaultRule.Negate;
                });
            }
        }
        else
        {
            // 检查并补全叶子规则的 RuleId
            EnsureRuleIdInConfigFile();
            
            services.Configure<Rule>(rulesetSection);
        }

        return services;
    }
    
    private static Rule CreateDefaultRule()
    {
        return new Rule
        {
            Operator = "OrElse",
            Rules = new List<Rule>
            {
                new Rule
                {
                    RuleId = GenerateRuleId(),
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".php" }
                },
                new Rule
                {
                    RuleId = GenerateRuleId(),
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".env" }
                },
                new Rule
                {
                    RuleId = GenerateRuleId(),
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".git" }
                }
            }
        };
    }
    
    /// <summary>检查并补全配置文件中所有规则的 RuleId，检测重复并自动修复，返回根 RuleId 值</summary>
    private static String EnsureRuleIdInConfigFile()
    {
        var newRuleId = GenerateRuleId();
        
        try
        {
            var possiblePaths = GetPossibleConfigPaths();
            String? targetPath = null;
            
            foreach (var path in possiblePaths)
            {
                if (File.Exists(path))
                {
                    targetPath = path;
                    break;
                }
            }
            
            if (targetPath == null) return newRuleId;
            
            var jsonContent = File.ReadAllText(targetPath);
            
            // 允许 JSON 中包含注释和尾随逗号
            var parseOptions = new System.Text.Json.JsonDocumentOptions
            {
                CommentHandling = System.Text.Json.JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };
            var nodeOptions = new System.Text.Json.Nodes.JsonNodeOptions
            {
                PropertyNameCaseInsensitive = true
            };
            var jsonNode = System.Text.Json.Nodes.JsonNode.Parse(jsonContent, nodeOptions, new System.Text.Json.JsonDocumentOptions
            {
                CommentHandling = System.Text.Json.JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            });
            
            if (jsonNode is not System.Text.Json.Nodes.JsonObject rootObj) return newRuleId;
            
            System.Text.Json.Nodes.JsonObject? rulesetObj = null;
            var rulesetKey = "Ruleset";
            
            if (rootObj.TryGetPropertyValue("Ruleset", out var rulesetNode))
            {
                rulesetObj = rulesetNode as System.Text.Json.Nodes.JsonObject;
                rulesetKey = "Ruleset";
            }
            else if (rootObj.TryGetPropertyValue("ruleset", out rulesetNode))
            {
                rulesetObj = rulesetNode as System.Text.Json.Nodes.JsonObject;
                rulesetKey = "ruleset";
            }
            
            if (rulesetObj == null) return newRuleId;
            
            // 递归处理所有叶子规则的 RuleId，收集已使用的 ID 并检测重复
            var usedIds = new HashSet<String>(StringComparer.OrdinalIgnoreCase);
            var missingRuleIds = new List<String>();
            var duplicateRuleIds = new List<String>();
            var modified = EnsureRuleIdsRecursive(rulesetObj, usedIds, missingRuleIds, duplicateRuleIds);
            
            // 如果有修改，提示用户（避免自动写回丢失注释）
            if (modified)
            {
                // 检查原始文件是否包含注释
                var hasComments = jsonContent.Contains("//") || jsonContent.Contains("/*");
                
                if (hasComments)
                {
                    // 文件包含注释，只输出警告，不自动写回
                    Console.WriteLine($"[WAF]:检测到配置文件包含注释，为避免丢失注释，请手动补全以下 RuleId:");
                    if (missingRuleIds.Count > 0)
                        Console.WriteLine($"  - 缺失 RuleId 的规则位置: {String.Join(", ", missingRuleIds)}");
                    if (duplicateRuleIds.Count > 0)
                        Console.WriteLine($"  - 重复的 RuleId: {String.Join(", ", duplicateRuleIds)}");
                    Console.WriteLine($"  - 配置文件路径: {targetPath}");
                }
                else
                {
                    // 无注释，安全写回
                    var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
                    var updatedJson = jsonNode.ToJsonString(jsonOptions);
                    File.WriteAllText(targetPath, updatedJson);
                    Console.WriteLine($"[WAF]:已自动补全/修复配置文件中的 RuleId - 文件:{targetPath}");
                }
            }
            
            return newRuleId;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Failed to update RuleId in config file: {ex.Message}");
        }
        
        return newRuleId;
    }
    
    /// <summary>递归处理规则对象，确保所有叶子规则都有唯一的 RuleId</summary>
    /// <param name="ruleObj">规则 JSON 对象</param>
    /// <param name="usedIds">已使用的 RuleId 集合</param>
    /// <param name="missingRuleIds">缺失 RuleId 的规则描述列表</param>
    /// <param name="duplicateRuleIds">重复的 RuleId 列表</param>
    /// <returns>是否有修改</returns>
    private static Boolean EnsureRuleIdsRecursive(
        System.Text.Json.Nodes.JsonObject ruleObj, 
        HashSet<String> usedIds,
        List<String> missingRuleIds,
        List<String> duplicateRuleIds)
    {
        var modified = false;
        
        // 检查是否有子规则（组合节点）
        System.Text.Json.Nodes.JsonArray? rulesArray = null;
        if (ruleObj.TryGetPropertyValue("rules", out var rulesNode) ||
            ruleObj.TryGetPropertyValue("Rules", out rulesNode))
        {
            rulesArray = rulesNode as System.Text.Json.Nodes.JsonArray;
        }
        
        // 判断是否为叶子节点（有 MemberName 或没有子 Rules 的规则）
        var hasMemberName = ruleObj.ContainsKey("memberName") || ruleObj.ContainsKey("MemberName");
        var isLeafRule = hasMemberName || rulesArray == null || rulesArray.Count == 0;
        
        // 只有叶子规则需要 RuleId
        if (isLeafRule && hasMemberName)
        {
            String? currentRuleId = null;
            var ruleIdKey = "ruleId";
            
            if (ruleObj.TryGetPropertyValue("ruleId", out var ruleIdNode))
            {
                currentRuleId = ruleIdNode?.GetValue<String>();
                ruleIdKey = "ruleId";
            }
            else if (ruleObj.TryGetPropertyValue("RuleId", out ruleIdNode))
            {
                currentRuleId = ruleIdNode?.GetValue<String>();
                ruleIdKey = "RuleId";
            }
            
            // 获取规则描述信息
            var memberName = ruleObj["memberName"]?.GetValue<String>() ?? ruleObj["MemberName"]?.GetValue<String>() ?? "unknown";
            var operatorName = ruleObj["operator"]?.GetValue<String>() ?? ruleObj["Operator"]?.GetValue<String>() ?? "unknown";
            var ruleDesc = $"{memberName}.{operatorName}";
            
            // 如果 RuleId 为空或重复，生成新的
            if (String.IsNullOrWhiteSpace(currentRuleId))
            {
                var newId = GenerateRuleId();
                while (usedIds.Contains(newId))
                {
                    newId = GenerateRuleId();
                }
                
                ruleObj[ruleIdKey] = newId;
                usedIds.Add(newId);
                modified = true;
                missingRuleIds.Add(ruleDesc);
            }
            else if (usedIds.Contains(currentRuleId))
            {
                var newId = GenerateRuleId();
                while (usedIds.Contains(newId))
                {
                    newId = GenerateRuleId();
                }
                
                ruleObj[ruleIdKey] = newId;
                usedIds.Add(newId);
                modified = true;
                duplicateRuleIds.Add(currentRuleId);
            }
            else
            {
                usedIds.Add(currentRuleId);
            }
        }
        
        // 递归处理子规则
        if (rulesArray != null)
        {
            foreach (var childNode in rulesArray)
            {
                if (childNode is System.Text.Json.Nodes.JsonObject childObj)
                {
                    if (EnsureRuleIdsRecursive(childObj, usedIds, missingRuleIds, duplicateRuleIds))
                    {
                        modified = true;
                    }
                }
            }
        }
        
        return modified;
    }
    
    /// <summary>生成 8 位短 GUID 作为 RuleId</summary>
    private static String GenerateRuleId() => Guid.NewGuid().ToString("N")[..8];
    
    private static void CreateDefaultConfigFile()
    {
        try
        {
            var possiblePaths = GetPossibleConfigPaths();
            string targetPath = null;
            
            // 找到第一个存在的Settings目录，或创建一个
            foreach (var path in possiblePaths)
            {
                var directory = Path.GetDirectoryName(path);
                if (Directory.Exists(directory))
                {
                    targetPath = path;
                    break;
                }
            }
            
            // 如果没有找到现有目录，尝试创建第一个可能的路径
            if (targetPath == null)
            {
                targetPath = possiblePaths[0];
                var directory = Path.GetDirectoryName(targetPath);
                Directory.CreateDirectory(directory);
            }
            
            // 如果文件不存在，则创建默认配置文件
            if (!File.Exists(targetPath))
            {
                var defaultConfig = new
                {
                    Ruleset = CreateDefaultRule()
                };
                
                var jsonOptions = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                
                var jsonString = JsonSerializer.Serialize(defaultConfig, jsonOptions);
                File.WriteAllText(targetPath, jsonString);
            }
        }
        catch (Exception ex)
        {
            // 如果创建文件失败，记录错误但不抛出异常，让程序继续使用内存配置
            Console.WriteLine($"Warning: Failed to create default WAF config file: {ex.Message}");
        }
    }
    
    private static List<string> GetPossibleConfigPaths()
    {
        var baseDirectory = AppContext.BaseDirectory;
        var paths = new List<string>
        {
            Path.Combine(baseDirectory, "Data", "Settings", "Ruleset.json"),
            Path.Combine(baseDirectory, "Settings", "Ruleset.json"),
            Path.Combine(Path.GetFullPath(Path.Combine(baseDirectory, "..")), "Settings", "Ruleset.json"),
            Path.Combine(baseDirectory, "bin", "Settings", "Ruleset.json")
        };
        
        return paths;
    }

    public static IApplicationBuilder UseWebFirewall(this IApplicationBuilder app)
    {
        app.UseMiddleware<WAFMiddleware>();

        return app;
    }
}
