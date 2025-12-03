using Microsoft.Extensions.Options;

using NewLife.Caching;
using NewLife.Log;

using Pek.Configs;

namespace Pek.WAF;

public class WAFMiddleware {
    #region 配置常量
    /// <summary>IP请求频率阈值（次数）</summary>
    private const Int32 IpRequestThreshold = 10;
    
    /// <summary>IP请求统计时间窗口（分钟）</summary>
    private const Int32 IpWindowMinutes = 5;
    #endregion

    private readonly RequestDelegate next;
    private Func<WebRequest, Boolean> compiledRule = default!;
    private readonly ICacheProvider cacheProvider;
    private readonly Object ruleLock = new();

    public WAFMiddleware(RequestDelegate next,
        ICacheProvider cache,
        IOptionsMonitor<Rule> ruleset)
    {
        this.next = next;
        cacheProvider = cache;

        UpdateCompiledRule(ruleset.CurrentValue);

        ruleset.OnChange(r => UpdateCompiledRule(r));
    }


    private void UpdateCompiledRule(Rule rule)
    {
        // 更新逻辑
        lock (ruleLock)
        {
            compiledRule = new MRE().CompileRule<WebRequest>(rule);
            XTrace.Log.Info($"[WAFMiddleware.UpdateCompiledRule]:规则已更新 - {rule}");
        }
    }

    public async Task Invoke(HttpContext context)
    {
        var wr = new WebRequest(context.Request, cacheProvider);

        // IP请求频率监控（由配置项控制）
        if (PekSysSetting.Current.EnableIpRateMonitor && !String.IsNullOrWhiteSpace(wr.RemoteIp))
        {
            var ipKey = $"WAF:ReqCount:{wr.RemoteIp}";
            var count = cacheProvider.Cache.Increment(ipKey, 1);
            
            // 首次计数时设置过期时间
            if (count == 1)
            {
                cacheProvider.Cache.SetExpire(ipKey, TimeSpan.FromMinutes(IpWindowMinutes));
            }
            
            XTrace.Log.Info($"[WAF]:IP请求监控 - IP:{wr.RemoteIp}, {IpWindowMinutes}分钟内请求:{count}次, Path:{wr.Path}, Method:{wr.Method}");
        }

        if (compiledRule(wr))
        {
            // Warn 级别:记录被拦截的请求详情
            XTrace.Log.Warn($"[WAFMiddleware.Invoke]:拦截请求 - IP:{wr.RemoteIp}, Path:{wr.Path}, Method:{wr.Method}, UserAgent:{wr.UserAgent}");

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await next.Invoke(context).ConfigureAwait(false);
    }
}
