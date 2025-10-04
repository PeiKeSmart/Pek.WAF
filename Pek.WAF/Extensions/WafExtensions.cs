namespace Pek.WAF.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System;

public static class WafExtensions {
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
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".php" }
                },
                new Rule
                {
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".env" }
                },
                new Rule
                {
                    MemberName = "Path",
                    Operator = "EndsWith",
                    Inputs = new List<object> { ".git" }
                }
            }
        };
    }
    
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
