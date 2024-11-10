namespace Pek.WAF.Extensions;

public static class WafExtensions {
    public static IServiceCollection AddWebFirewall(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<Rule>(opt => configuration.GetSection("Ruleset").Bind(opt));


        return services;
    }

    public static IApplicationBuilder UseWebFirewall(this IApplicationBuilder app)
    {
        app.UseMiddleware<WAFMiddleware>();

        return app;
    }
}
