namespace Pek.WAF.Extensions;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using System.Collections.Generic;

public static class WafExtensions {
    public static IServiceCollection AddWebFirewall(this IServiceCollection services, IConfiguration configuration)
    {
        var rulesetSection = configuration.GetSection("Ruleset");
        
        // 如果配置中没有Ruleset节点，则创建默认配置
        if (!rulesetSection.Exists())
        {
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

    public static IApplicationBuilder UseWebFirewall(this IApplicationBuilder app)
    {
        app.UseMiddleware<WAFMiddleware>();

        return app;
    }
}
