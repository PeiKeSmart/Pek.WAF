using Microsoft.Extensions.Options;

using NewLife.Caching;
using NewLife.Log;

using Pek.Configs;

namespace Pek.WAF;

public class WAFMiddleware {
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

        // 这条日志一定会输出，用来确认 Invoke 是否被调用（使用 DHWeb.GetUserHost 获取真实客户端 IP）
        XTrace.Log.Warn($"[WAFMiddleware.Invoke]:请求到达 - IP:{wr.RemoteIp}, Path:{context.Request.Path}");

        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        var allowDetailLog = PekSysSetting.Current.AllowRequestParams || XTrace.Log.Level <= NewLife.Log.LogLevel.Debug;
        
        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[WAFMiddleware.Invoke]:评估请求 - IP:{wr.RemoteIp}, Path:{wr.Path}, Method:{wr.Method}");
        }

        if (compiledRule(wr))
        {
            // Warn 级别：记录被拦截的请求详情
            XTrace.Log.Warn($"[WAFMiddleware.Invoke]:拦截请求 - IP:{wr.RemoteIp}, Path:{wr.Path}, Method:{wr.Method}, UserAgent:{wr.UserAgent}");

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await next.Invoke(context).ConfigureAwait(false);
    }
}
