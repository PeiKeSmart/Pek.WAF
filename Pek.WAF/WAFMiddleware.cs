using Microsoft.Extensions.Options;

using NewLife.Caching;
using NewLife.Log;

using Pek.Configs;
using Pek.WAF.Extensions;

namespace Pek.WAF;

public class WAFMiddleware
{
    #region 配置常量
    /// <summary>IP请求频率阈值（次数）</summary>
    private const Int32 IpRequestThreshold = 10;
    
    /// <summary>IP请求统计时间窗口（分钟）</summary>
    private const Int32 IpWindowMinutes = 5;
    #endregion

    private readonly RequestDelegate _next;
    private readonly ICacheProvider _cacheProvider;

    /// <summary>编译后的规则委托，使用 volatile 保证可见性，配合 Interlocked.Exchange 实现无锁更新</summary>
    private volatile Func<WebRequest, Boolean> _compiledRule = default!;

    public WAFMiddleware(RequestDelegate next,
        ICacheProvider cache,
        IOptionsMonitor<Rule> ruleset)
    {
        _next = next;
        _cacheProvider = cache;

        UpdateCompiledRule(ruleset.CurrentValue);

        ruleset.OnChange(r => UpdateCompiledRule(r));
    }

    private void UpdateCompiledRule(Rule rule)
    {
        // 预解析并更新规则缓存
        PreparseRuleCaches(rule);
        
        // 编译新规则
        var newCompiledRule = new MRE().CompileRule<WebRequest>(rule);
        
        // 原子替换：无锁更新，读取时无需任何同步开销
        Interlocked.Exchange(ref _compiledRule, newCompiledRule);
        
        XTrace.Log.Info($"[WAFMiddleware.UpdateCompiledRule]:规则已更新 - {rule}");
    }
    
    /// <summary>递归预解析规则并更新缓存</summary>
    private void PreparseRuleCaches(Rule rule)
    {
        if (rule == null) return;
        
        // 如果是叶子规则且有 RuleId 和 Inputs，预解析并写入缓存
        if (!String.IsNullOrWhiteSpace(rule.RuleId) && rule.Inputs?.Count > 0)
        {
            var input = rule.Inputs[0]?.ToString();
            if (!String.IsNullOrWhiteSpace(input))
            {
                switch (rule.Operator)
                {
                    case "IsInIpList":
                    case "IsNotInIpList":
                        var ipRules = WebRequest.ParseIpList(input);
                        _cacheProvider.Cache.Set(BuildCacheKey($"IPList:{rule.RuleId}"), ipRules, 300);
                        break;
                    case "ContainsUserAgent":
                    case "NotContainsUserAgent":
                        var keywords = input.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        _cacheProvider.Cache.Set(BuildCacheKey($"UAKeywords:{rule.RuleId}"), keywords, 300);
                        break;
                    case "IsInUserAgentList":
                    case "IsNotInUserAgentList":
                        var agents = input.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        _cacheProvider.Cache.Set(BuildCacheKey($"UAList:{rule.RuleId}"), agents, 300);
                        break;
                    case "UserAgentStartsWith":
                        var prefixes = input.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        _cacheProvider.Cache.Set(BuildCacheKey($"UAPrefixes:{rule.RuleId}"), prefixes, 300);
                        break;
                }
            }
        }
        
        // 递归处理子规则
        if (rule.Rules != null)
        {
            foreach (var childRule in rule.Rules)
            {
                PreparseRuleCaches(childRule);
            }
        }
    }

    /// <summary>构建带前缀的缓存键</summary>
    private static String BuildCacheKey(String suffix) => $"{RedisSetting.Current.CacheKeyPrefix}:WAF:{suffix}";

    public async Task Invoke(HttpContext context)
    {
        var wr = new WebRequest(context.Request, _cacheProvider);

        // IP请求频率监控（由配置项控制）
        if (PekSysSetting.Current.EnableIpRateMonitor && !String.IsNullOrWhiteSpace(wr.RemoteIp))
        {
            var ipKey = BuildCacheKey($"ReqCount:{wr.RemoteIp}");
            
            // 使用 Add 原子操作：仅当 key 不存在时初始化为 0 并设置过期时间
            // Add 返回 true 表示 key 不存在并成功添加，false 表示 key 已存在
            // 这样无论多少并发请求同时到达，只有一个会成功初始化
            _cacheProvider.Cache.Add(ipKey, 0, IpWindowMinutes * 60);
            
            // Increment 原子递增，无论 Add 是否成功都执行
            var count = _cacheProvider.Cache.Increment(ipKey, 1);
            
            // 仅在调试模式时输出详细日志，避免高并发下的日志性能开销
            if (XTrace.Log.Level <= NewLife.Log.LogLevel.Debug)
            {
                XTrace.Log.Debug($"[WAF]:IP请求监控 - IP:{wr.RemoteIp}, {IpWindowMinutes}分钟内请求:{count}次, Path:{wr.Path}, Method:{wr.Method}");
            }
        }

        // 读取 volatile 字段：无锁，性能最优
        var rule = _compiledRule;
        if (rule(wr))
        {
            // Warn 级别:记录被拦截的请求详情
            XTrace.Log.Warn($"[WAFMiddleware.Invoke]:拦截请求 - IP:{wr.RemoteIp}, Path:{wr.Path}, Method:{wr.Method}, UserAgent:{wr.UserAgent}");

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await _next.Invoke(context).ConfigureAwait(false);
    }
}
