using Microsoft.Extensions.Options;

using NewLife.Caching;
using NewLife.Common;
using NewLife.Log;
using NewLife.Serialization;

namespace Pek.WAF;

public class WAFMiddleware
{
    private readonly RequestDelegate next;
    private Func<WebRequest, Boolean> compiledRule = default!;
    private readonly ICacheProvider cacheProvider;
    private readonly object ruleLock = new object();

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
        }
    }

    public async Task Invoke(HttpContext context)
    {
        var wr = new WebRequest(context.Request, cacheProvider);

        if (compiledRule(wr))
        {
            XTrace.Log.Warn($"Forbidden request from {wr.RemoteIp}");

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        await next.Invoke(context);
    }
}
