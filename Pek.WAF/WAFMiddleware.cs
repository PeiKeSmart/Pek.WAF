using Microsoft.Extensions.Options;

using NewLife.Caching;
using NewLife.Log;

namespace Pek.WAF;

public class WAFMiddleware
{
    private readonly RequestDelegate next;
    private readonly Func<WebRequest, Boolean> compiledRule;
    private readonly ICacheProvider cacheProvider;

    public WAFMiddleware(RequestDelegate next,
        ICacheProvider cache,
        IOptions<Rule> ruleset)
    {
        this.next = next;

        compiledRule = new MRE().CompileRule<WebRequest>(ruleset.Value);

        cacheProvider = cache;
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
