using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace Pek.WAF.Extensions;

/// <summary>String类型的UserAgent相关扩展方法，用于WAF规则引擎</summary>
public static class StringUserAgentExtensions
{
    #region 静态缓存
    /// <summary>字符串分割结果缓存，避免重复分割操作（规则配置数量有限，无需容量限制）</summary>
    private static readonly ConcurrentDictionary<String, String[]> _splitCache = new(StringComparer.Ordinal);
    
    /// <summary>编译后的正则表达式缓存，避免重复编译开销</summary>
    private static readonly ConcurrentDictionary<String, Regex?> _regexCache = new(StringComparer.Ordinal);
    #endregion

    /// <summary>检查UserAgent是否包含任意一个指定的关键字（不区分大小写）</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔，如: "bot, spider, crawler"</param>
    /// <returns>如果包含任意关键字返回true，否则返回false</returns>
    public static Boolean ContainsAny(this String? userAgent, String keywords)
    {
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(keywords))
            return false;

        var keywordArray = GetOrAddSplitCache(keywords);
        
        foreach (var keyword in keywordArray)
        {
            if (String.IsNullOrEmpty(keyword))
                continue;

            if (userAgent.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查UserAgent是否不包含任意一个指定的关键字（白名单模式）</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔</param>
    /// <returns>如果不包含任何关键字返回true，否则返回false</returns>
    public static Boolean NotContainsAny(this String? userAgent, String keywords) => !ContainsAny(userAgent, keywords);

    /// <summary>检查UserAgent是否在指定的UserAgent列表中（精确匹配，不区分大小写）</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果在列表中返回true，否则返回false</returns>
    public static Boolean IsInUserAgentList(this String? userAgent, String userAgentList)
    {
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(userAgentList))
            return false;

        var agents = GetOrAddSplitCache(userAgentList);

        foreach (var agent in agents)
        {
            if (String.IsNullOrEmpty(agent))
                continue;

            if (String.Equals(userAgent, agent, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查UserAgent是否不在指定的UserAgent列表中（白名单模式）</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果不在列表中返回true，否则返回false</returns>
    public static Boolean IsNotInUserAgentList(this String? userAgent, String userAgentList) => !IsInUserAgentList(userAgent, userAgentList);

    /// <summary>检查UserAgent是否以指定的任意前缀开头（不区分大小写）</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="prefixes">前缀列表，多个前缀用逗号或分号分隔，如: "Mozilla, Chrome, Safari"</param>
    /// <returns>如果以任意前缀开头返回true，否则返回false</returns>
    public static Boolean StartsWithAny(this String? userAgent, String prefixes)
    {
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(prefixes))
            return false;

        var prefixArray = GetOrAddSplitCache(prefixes);

        foreach (var prefix in prefixArray)
        {
            if (String.IsNullOrEmpty(prefix))
                continue;

            if (userAgent.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查UserAgent是否匹配正则表达式模式</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <param name="pattern">正则表达式模式</param>
    /// <returns>如果匹配返回true，否则返回false</returns>
    public static Boolean MatchesPattern(this String? userAgent, String pattern)
    {
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(pattern))
            return false;

        var regex = GetOrAddRegexCache(pattern);
        if (regex == null)
            return false;

        try
        {
            return regex.IsMatch(userAgent);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>检查UserAgent是否为空或未提供</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <returns>如果为空或null返回true，否则返回false</returns>
    public static Boolean IsEmpty(this String? userAgent) => String.IsNullOrWhiteSpace(userAgent);

    /// <summary>检查UserAgent是否不为空</summary>
    /// <param name="userAgent">要检查的UserAgent字符串</param>
    /// <returns>如果不为空返回true，否则返回false</returns>
    public static Boolean IsNotEmpty(this String? userAgent) => !String.IsNullOrWhiteSpace(userAgent);

    #region 缓存辅助方法
    /// <summary>获取或添加字符串分割缓存</summary>
    private static String[] GetOrAddSplitCache(String input) =>
        _splitCache.GetOrAdd(input, k => k.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    
    /// <summary>获取或添加正则表达式缓存</summary>
    private static Regex? GetOrAddRegexCache(String pattern) =>
        _regexCache.GetOrAdd(pattern, k =>
        {
            try
            {
                // 使用 Compiled 选项编译正则表达式，提升匹配性能
                return new Regex(k, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromMilliseconds(100));
            }
            catch
            {
                return null;
            }
        });
    #endregion
}
