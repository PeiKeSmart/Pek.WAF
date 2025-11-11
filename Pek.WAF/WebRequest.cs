using System.Net;
using System.Net.Sockets;

using Microsoft.Net.Http.Headers;

using NewLife.Caching;

using Pek.Configs;
using Pek.Helpers;
using Pek.Webs;

#if NET8_0_OR_GREATER
using IPNetwork = System.Net.IPNetwork;
#endif

namespace Pek.WAF;

public record WebRequest(HttpRequest request, ICacheProvider cacheProvider)
{
    private String? _remoteIpCache;

    public String? Method => request.Method;

    public String? Path => request.Path.Value;

    public String? QueryString => request.QueryString.Value;

    public String? Referer => request.Headers[HeaderNames.Referer].ToString();

    public String? UserAgent => request.HttpContext.Request.Headers.UserAgent.ToString();

    /// <summary>
    /// 获取远程 IP 地址（通过 DHWeb.GetUserHost 获取真实客户端 IP，自动支持代理转发）
    /// </summary>
    public String? RemoteIp => _remoteIpCache ??= DHWeb.GetUserHost(request.HttpContext);

    public Boolean Authenticated => request.HttpContext.User.Identity?.IsAuthenticated == true;

    //private String? ipCountry;

    //public String? IpCountry
    //{
    //    get
    //    {
    //        if (ipCountry == null)
    //        {
    //            var data = geo.Lookup(request.HttpContext.Connection.RemoteIpAddress);
    //            if (data != null)
    //            {
    //                var cnty = data["country"] as Dictionary<string, object>;
    //                ipCountry = (string)cnty["isocode"];
    //            }
    //        }

    //        return ipCountry;
    //    }
    //}

    public Boolean InSubnet(String ip, Int32 mask)
    {
        // 使用 RemoteIp（DHWeb.GetUserHost）获取真实客户端 IP
        var remoteIpStr = RemoteIp;
        if (String.IsNullOrWhiteSpace(remoteIpStr) || !IPAddress.TryParse(remoteIpStr, out var remoteIpAddress))
        {
            return false;
        }

#if NET8_0_OR_GREATER
        var network = new IPNetwork(IPAddress.Parse(ip), mask);
        var result = network.Contains(remoteIpAddress);
#elif NET6_0 || NET7_0
        var ipAddress = IPAddress.Parse(ip);

        var ipBytes = ipAddress.GetAddressBytes();
        var remoteIpBytes = remoteIpAddress.GetAddressBytes();
        var maskBytes = BitConverter.GetBytes(~((1 << (32 - mask)) - 1));

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(maskBytes);
        }

        var result = true;
        for (var i = 0; i < ipBytes.Length; i++)
        {
            if ((ipBytes[i] & maskBytes[i]) != (remoteIpBytes[i] & maskBytes[i]))
            {
                result = false;
                break;
            }
        }
#endif
        
        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        if (PekSysSetting.Current.AllowRequestParams || NewLife.Log.XTrace.Log.Level <= NewLife.Log.LogLevel.Debug)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.InSubnet]:子网检查 - RemoteIP:{RemoteIp}, 网络:{ip}/{mask}, 匹配:{result}");
        }
        
        return result;
    }

    public Boolean IpInFile(String path)
    {
        var keyname = System.IO.Path.GetFileNameWithoutExtension(path);

        var data = cacheProvider.Cache.Get<IEnumerable<String>>(keyname);
        if (data == null && File.Exists(path))
        {
            data = File.ReadAllLines(path);
            cacheProvider.Cache.Set<IEnumerable<String>>(keyname, data, 15 * 60);
            
            // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
            if (PekSysSetting.Current.AllowRequestParams || NewLife.Log.XTrace.Log.Level <= NewLife.Log.LogLevel.Debug)
            {
                NewLife.Log.XTrace.Log.Debug($"[WebRequest.IpInFile]:加载IP文件 - 文件:{path}, IP数量:{data.Count()}");
            }
        }

        var result = data?.Contains(RemoteIp, StringComparer.OrdinalIgnoreCase) ?? false;
        
        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        if (PekSysSetting.Current.AllowRequestParams || NewLife.Log.XTrace.Log.Level <= NewLife.Log.LogLevel.Debug)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.IpInFile]:IP文件检查 - RemoteIP:{RemoteIp}, 文件:{path}, 匹配:{result}");
        }
        
        return result;
    }

    /// <summary>检查当前请求的远程IP是否在指定的IP列表中</summary>
    /// <param name="ipList">IP列表字符串，支持多种格式：
    /// - 精确匹配: 192.168.1.100
    /// - CIDR格式: 192.168.1.0/24
    /// - 通配符: 192.168.*.* 或 10.0.1.*
    /// - 多个IP用逗号或分号分隔: 192.168.1.1, 192.168.1.2; 10.0.0.1
    /// </param>
    /// <returns>如果IP在列表中返回true，否则返回false</returns>
    public Boolean IsInIpList(String ipList)
    {
        // 使用 RemoteIp（DHWeb.GetUserHost）获取真实客户端 IP
        var remoteIpStr = RemoteIp;
        if (String.IsNullOrWhiteSpace(remoteIpStr) || String.IsNullOrWhiteSpace(ipList))
            return false;

        // 尝试解析为 IPAddress 对象（用于 CIDR 子网检查）
        IPAddress? remoteIpAddress = null;
        if (!IPAddress.TryParse(remoteIpStr, out remoteIpAddress))
        {
            return false;
        }

        // 尝试从缓存获取解析后的规则
        var cacheKey = $"IPList:{ipList}";
        var parsedRules = cacheProvider.Cache.Get<ParsedIpRule[]>(cacheKey);
        
        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        var allowDetailLog = PekSysSetting.Current.AllowRequestParams || NewLife.Log.XTrace.Log.Level <= NewLife.Log.LogLevel.Debug;
        
        if (parsedRules == null)
        {
            parsedRules = ParseIpList(ipList);
            cacheProvider.Cache.Set(cacheKey, parsedRules, 300); // 缓存5分钟
            
            if (allowDetailLog)
            {
                NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:解析IP列表 - 规则数量:{parsedRules.Length}, 原始列表:{ipList}");
            }
        }

        // 快速匹配
        foreach (var rule in parsedRules)
        {
            var matched = false;
            
            if (rule.Type == IpRuleType.Exact)
            {
                matched = String.Equals(remoteIpStr, rule.Value, StringComparison.Ordinal);
            }
            else if (rule.Type == IpRuleType.Cidr)
            {
                if (rule.Mask.HasValue)
                    matched = IsInSubnetFast(remoteIpAddress, rule.ParsedIp!, rule.Mask.Value);
            }
            else if (rule.Type == IpRuleType.Wildcard)
            {
                matched = MatchWildcardIpFast(remoteIpStr, rule.Value!);
            }
            
            if (matched)
            {
                if (allowDetailLog)
                {
                    NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:IP匹配成功 - RemoteIP:{remoteIpStr}, 规则类型:{rule.Type}, 规则值:{rule.Value}");
                }
                return true;
            }
        }

        if (allowDetailLog)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:IP不在列表 - RemoteIP:{remoteIpStr}, 已检查规则数:{parsedRules.Length}");
        }

        return false;
    }

    /// <summary>检查当前请求的远程IP是否不在指定的IP列表中（白名单模式）</summary>
    /// <param name="ipList">IP列表字符串，格式同IsInIpList</param>
    /// <returns>如果IP不在列表中返回true，否则返回false</returns>
    public Boolean IsNotInIpList(String ipList) => !IsInIpList(ipList);

    /// <summary>检查当前请求的UserAgent是否包含指定列表中的任意关键字</summary>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔，如: "bot, spider, crawler"</param>
    /// <returns>如果包含任意关键字返回true，否则返回false</returns>
    public Boolean ContainsUserAgent(String keywords)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(keywords))
            return false;

        // 缓存关键字数组，避免重复分割
        var cacheKey = $"UAKeywords:{keywords}";
        var keywordArray = cacheProvider.Cache.Get<String[]>(cacheKey);
        
        if (keywordArray == null)
        {
            keywordArray = keywords.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            cacheProvider.Cache.Set(cacheKey, keywordArray, 300); // 缓存5分钟
        }

        foreach (var keyword in keywordArray)
        {
            if (!String.IsNullOrEmpty(keyword) && userAgent.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查当前请求的UserAgent是否不包含指定列表中的任意关键字（白名单模式）</summary>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔</param>
    /// <returns>如果不包含任何关键字返回true，否则返回false</returns>
    public Boolean NotContainsUserAgent(String keywords) => !ContainsUserAgent(keywords);

    /// <summary>检查当前请求的UserAgent是否在指定的UserAgent列表中（精确匹配）</summary>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果在列表中返回true，否则返回false</returns>
    public Boolean IsInUserAgentList(String userAgentList)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(userAgentList))
            return false;

        // 缓存UserAgent数组，避免重复分割
        var cacheKey = $"UAList:{userAgentList}";
        var agents = cacheProvider.Cache.Get<String[]>(cacheKey);
        
        if (agents == null)
        {
            agents = userAgentList.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            cacheProvider.Cache.Set(cacheKey, agents, 300); // 缓存5分钟
        }

        foreach (var agent in agents)
        {
            if (!String.IsNullOrEmpty(agent) && String.Equals(userAgent, agent, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查当前请求的UserAgent是否不在指定的UserAgent列表中（白名单模式）</summary>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果不在列表中返回true，否则返回false</returns>
    public Boolean IsNotInUserAgentList(String userAgentList) => !IsInUserAgentList(userAgentList);

    /// <summary>检查当前请求的UserAgent是否以指定的任意前缀开头</summary>
    /// <param name="prefixes">前缀列表，多个前缀用逗号或分号分隔</param>
    /// <returns>如果以任意前缀开头返回true，否则返回false</returns>
    public Boolean UserAgentStartsWith(String prefixes)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(prefixes))
            return false;

        // 缓存前缀数组
        var cacheKey = $"UAPrefixes:{prefixes}";
        var prefixArray = cacheProvider.Cache.Get<String[]>(cacheKey);
        
        if (prefixArray == null)
        {
            prefixArray = prefixes.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            cacheProvider.Cache.Set(cacheKey, prefixArray, 300); // 缓存5分钟
        }

        foreach (var prefix in prefixArray)
        {
            if (!String.IsNullOrEmpty(prefix) && userAgent.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查当前请求的UserAgent是否为空或未提供</summary>
    /// <returns>如果为空返回true，否则返回false</returns>
    public Boolean UserAgentIsEmpty() => String.IsNullOrWhiteSpace(UserAgent);

    /// <summary>检查当前请求的UserAgent是否不为空</summary>
    /// <returns>如果不为空返回true，否则返回false</returns>
    public Boolean UserAgentIsNotEmpty() => !String.IsNullOrWhiteSpace(UserAgent);

    private static ParsedIpRule[] ParseIpList(String ipList)
    {
        var entries = ipList.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var rules = new List<ParsedIpRule>(entries.Length);

        foreach (var entry in entries)
        {
            if (String.IsNullOrEmpty(entry))
                continue;

            // CIDR 格式
            var slashIdx = entry.IndexOf('/');
            if (slashIdx > 0 && slashIdx < entry.Length - 1)
            {
                if (Int32.TryParse(entry.AsSpan(slashIdx + 1), out var mask) && 
                    IPAddress.TryParse(entry.AsSpan(0, slashIdx), out var ip))
                {
                    rules.Add(new ParsedIpRule(IpRuleType.Cidr, entry, ip, mask));
                    continue;
                }
            }

            // 通配符格式
            if (entry.IndexOf('*') >= 0)
            {
                rules.Add(new ParsedIpRule(IpRuleType.Wildcard, entry, null, null));
                continue;
            }

            // 精确匹配
            rules.Add(new ParsedIpRule(IpRuleType.Exact, entry, null, null));
        }

        return [.. rules];
    }

    private static Boolean IsInSubnetFast(IPAddress remoteIp, IPAddress networkIp, Int32 mask)
    {
#if NET8_0_OR_GREATER
        var network = new IPNetwork(networkIp, mask);
        return network.Contains(remoteIp);
#else
        if (remoteIp.AddressFamily != networkIp.AddressFamily)
            return false;

        var remoteBytes = remoteIp.GetAddressBytes();
        var networkBytes = networkIp.GetAddressBytes();
        
        if (remoteIp.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4
            var maskValue = mask >= 32 ? 0 : ~((1u << (32 - mask)) - 1);
            var maskBytes = BitConverter.GetBytes(maskValue);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(maskBytes);

            for (var i = 0; i < 4; i++)
            {
                if ((remoteBytes[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i]))
                    return false;
            }
            return true;
        }
        else
        {
            // IPv6
            var fullBytes = mask / 8;
            var remainingBits = mask % 8;

            for (var i = 0; i < fullBytes; i++)
            {
                if (remoteBytes[i] != networkBytes[i])
                    return false;
            }

            if (remainingBits > 0 && fullBytes < remoteBytes.Length)
            {
                var maskByte = (Byte)(0xFF << (8 - remainingBits));
                if ((remoteBytes[fullBytes] & maskByte) != (networkBytes[fullBytes] & maskByte))
                    return false;
            }

            return true;
        }
#endif
    }

    private static Boolean MatchWildcardIpFast(ReadOnlySpan<Char> ip, ReadOnlySpan<Char> pattern)
    {
        var ipSegments = 0;
        var patternSegments = 0;
        var ipStart = 0;
        var patternStart = 0;

        for (var i = 0; i <= ip.Length && i <= pattern.Length; i++)
        {
            var ipEnded = i == ip.Length || (i < ip.Length && ip[i] == '.');
            var patternEnded = i == pattern.Length || (i < pattern.Length && pattern[i] == '.');

            if (ipEnded && patternEnded)
            {
                var ipSegment = ip.Slice(ipStart, i - ipStart);
                var patternSegment = pattern.Slice(patternStart, i - patternStart);

                if (patternSegment.Length == 1 && patternSegment[0] == '*')
                {
                    // 通配符匹配，跳过
                }
                else if (!ipSegment.SequenceEqual(patternSegment))
                {
                    return false;
                }

                ipSegments++;
                patternSegments++;
                ipStart = i + 1;
                patternStart = i + 1;

                if (i == ip.Length && i == pattern.Length)
                    break;
            }
            else if (ipEnded != patternEnded)
            {
                return false;
            }
        }

        return ipSegments == 4 && patternSegments == 4;
    }

    private enum IpRuleType : byte
    {
        Exact,
        Cidr,
        Wildcard
    }

    private readonly record struct ParsedIpRule(IpRuleType Type, String Value, IPAddress? ParsedIp, Int32? Mask);
}
