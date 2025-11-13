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

        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        var allowDetailLog = PekSysSetting.Current.AllowRequestParams || XTrace.Log.Level <= NewLife.Log.LogLevel.Debug;
        
        // IP请求频率统计（轻量级计数器）
        if (!String.IsNullOrWhiteSpace(wr.RemoteIp))
        {
            var ipKey = $"WAF:ReqCount:{wr.RemoteIp}";
            var count = cacheProvider.Cache.Increment(ipKey, 1);
            
            // 首次计数时设置过期时间
            if (count == 1)
            {
                cacheProvider.Cache.SetExpire(ipKey, TimeSpan.FromMinutes(IpWindowMinutes));
            }
            
            // 超过阈值时记录告警日志
            if (count >= IpRequestThreshold)
            {
                XTrace.Log.Warn($"[WAF]:高频IP检测 - IP:{wr.RemoteIp}, {IpWindowMinutes}分钟内请求:{count}次, Path:{wr.Path}, Method:{wr.Method}");
            }
        }
        
        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[WAFMiddleware.Invoke]:评估请求 - IP:{wr.RemoteIp}, Path:{wr.Path}, Method:{wr.Method}");
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
