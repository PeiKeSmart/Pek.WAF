using System.Net;
using System.Net.Sockets;

using Microsoft.Net.Http.Headers;

using NewLife.Caching;

using Pek.Configs;
using Pek.Helpers;
using Pek.WAF.Extensions;
using Pek.Webs;

#if NET8_0_OR_GREATER
using IPNetwork = System.Net.IPNetwork;
#endif

namespace Pek.WAF;

public record WebRequest(HttpRequest request, ICacheProvider cacheProvider)
{
    private String? _remoteIpCache;

    /// <summary>是否允许输出详细日志（请求级缓存，避免重复检查配置）</summary>
    private readonly Boolean _allowDetailLog = PekSysSetting.Current.AllowRequestParams || NewLife.Log.XTrace.Log.Level <= NewLife.Log.LogLevel.Debug;

    public String? Method => request.Method;

    public String? Path => request.Path.Value;

    public String? QueryString => request.QueryString.Value;

    public String? Referer => request.Headers[HeaderNames.Referer].ToString();

    /// <summary>
    /// 获取 User-Agent（通过 DHWeb.UserAgent 统一获取）
    /// </summary>
    public String? UserAgent => DHWeb.UserAgent;

    /// <summary>
    /// 获取远程 IP 地址（通过 DHWeb.GetUserHost 获取真实客户端 IP，自动支持代理转发）
    /// </summary>
    public String? RemoteIp => _remoteIpCache ??= DHWeb.GetUserHost(request.HttpContext);

    public Boolean Authenticated => request.HttpContext.User.Identity?.IsAuthenticated == true;

    /// <summary>构建带前缀的缓存键</summary>
    private static String BuildCacheKey(String suffix) => $"{RedisSetting.Current.CacheKeyPrefix}:WAF:{suffix}";

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
        
        if (_allowDetailLog)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.InSubnet]:子网检查 - RemoteIP:{RemoteIp}, 网络:{ip}/{mask}, 匹配:{result}");
        }
        
        return result;
    }

    public Boolean IpInFile(String path)
    {
        var keyname = BuildCacheKey($"IPFile:{System.IO.Path.GetFileNameWithoutExtension(path)}");

        // 使用 GetOrAdd 确保并发首次请求时只有一个线程读取文件
        // 使用 HashSet 实现 O(1) 查找，替代数组的 O(n) 线性查找
        var data = cacheProvider.Cache.GetOrAdd<HashSet<String>>(keyname, k =>
        {
            if (!File.Exists(path))
                return [];
                
            var lines = File.ReadAllLines(path);
            var hashSet = new HashSet<String>(lines, StringComparer.OrdinalIgnoreCase);
            
            if (_allowDetailLog)
            {
                NewLife.Log.XTrace.Log.Debug($"[WebRequest.IpInFile]:加载IP文件 - 文件:{path}, IP数量:{hashSet.Count}");
            }
            
            return hashSet;
        }, 15 * 60);

        var result = data.Count > 0 && data.Contains(RemoteIp!);
        
        if (_allowDetailLog)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.IpInFile]:IP文件检查 - RemoteIP:{RemoteIp}, 文件:{path}, 匹配:{result}");
        }
        
        return result;
    }

    /// <summary>检查当前请求的远程IP是否在指定的IP列表中</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="ipList">IP列表字符串，支持多种格式：
    /// - 精确匹配: 192.168.1.100
    /// - CIDR格式: 192.168.1.0/24
    /// - 通配符: 192.168.*.* 或 10.0.1.*
    /// - 多个IP用逗号或分号分隔: 192.168.1.1, 192.168.1.2; 10.0.0.1
    /// </param>
    /// <returns>如果IP在列表中返回true，否则返回false</returns>
    public Boolean IsInIpList(String ruleId, String ipList)
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

        // 使用 RuleId 作为缓存键，规则变化时在中间件中主动更新缓存
        var cacheKey = BuildCacheKey($"IPList:{ruleId}");
        var parsedRules = cacheProvider.Cache.GetOrAdd(cacheKey, k =>
        {
            var rules = ParseIpList(ipList);
            
            if (_allowDetailLog)
            {
                NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:解析IP列表 - RuleId:{ruleId}, 规则数量:{rules.Length}");
            }
            
            return rules;
        }, 300); // 缓存5分钟

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
                if (_allowDetailLog)
                {
                    NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:IP匹配成功 - RemoteIP:{remoteIpStr}, RuleId:{ruleId}, 规则类型:{rule.Type}");
                }
                return true;
            }
        }

        if (_allowDetailLog)
        {
            NewLife.Log.XTrace.Log.Debug($"[WebRequest.IsInIpList]:IP不在列表 - RemoteIP:{remoteIpStr}, RuleId:{ruleId}");
        }

        return false;
    }

    /// <summary>检查当前请求的远程IP是否不在指定的IP列表中（白名单模式）</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="ipList">IP列表字符串，格式同IsInIpList</param>
    /// <returns>如果IP不在列表中返回true，否则返回false</returns>
    public Boolean IsNotInIpList(String ruleId, String ipList) => !IsInIpList(ruleId, ipList);

    /// <summary>检查当前请求的UserAgent是否包含指定列表中的任意关键字</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔，如: "bot, spider, crawler"</param>
    /// <returns>如果包含任意关键字返回true，否则返回false</returns>
    public Boolean ContainsUserAgent(String ruleId, String keywords)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(keywords))
            return false;

        // 使用 RuleId 作为缓存键
        var cacheKey = BuildCacheKey($"UAKeywords:{ruleId}");
        var keywordArray = cacheProvider.Cache.GetOrAdd(cacheKey, 
            k => keywords.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), 
            300); // 缓存5分钟

        foreach (var keyword in keywordArray)
        {
            if (!String.IsNullOrEmpty(keyword) && userAgent.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查当前请求的UserAgent是否不包含指定列表中的任意关键字（白名单模式）</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="keywords">关键字列表，多个关键字用逗号或分号分隔</param>
    /// <returns>如果不包含任何关键字返回true，否则返回false</returns>
    public Boolean NotContainsUserAgent(String ruleId, String keywords) => !ContainsUserAgent(ruleId, keywords);

    /// <summary>检查当前请求的UserAgent是否在指定的UserAgent列表中（精确匹配）</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果在列表中返回true，否则返回false</returns>
    public Boolean IsInUserAgentList(String ruleId, String userAgentList)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(userAgentList))
            return false;

        // 使用 RuleId 作为缓存键，使用 HashSet 实现 O(1) 精确匹配
        var cacheKey = BuildCacheKey($"UAList:{ruleId}");
        var agents = cacheProvider.Cache.GetOrAdd(cacheKey, 
            k => new HashSet<String>(
                userAgentList.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.OrdinalIgnoreCase), 
            300); // 缓存5分钟

        return agents.Contains(userAgent);
    }

    /// <summary>检查当前请求的UserAgent是否不在指定的UserAgent列表中（白名单模式）</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="userAgentList">UserAgent列表，多个值用逗号或分号分隔</param>
    /// <returns>如果不在列表中返回true，否则返回false</returns>
    public Boolean IsNotInUserAgentList(String ruleId, String userAgentList) => !IsInUserAgentList(ruleId, userAgentList);

    /// <summary>检查当前请求的UserAgent是否以指定的任意前缀开头</summary>
    /// <param name="ruleId">规则唯一标识，用于缓存键</param>
    /// <param name="prefixes">前缀列表，多个前缀用逗号或分号分隔</param>
    /// <returns>如果以任意前缀开头返回true，否则返回false</returns>
    public Boolean UserAgentStartsWith(String ruleId, String prefixes)
    {
        var userAgent = UserAgent;
        if (String.IsNullOrWhiteSpace(userAgent) || String.IsNullOrWhiteSpace(prefixes))
            return false;

        // 使用 RuleId 作为缓存键
        var cacheKey = BuildCacheKey($"UAPrefixes:{ruleId}");
        var prefixArray = cacheProvider.Cache.GetOrAdd(cacheKey, 
            k => prefixes.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), 
            300); // 缓存5分钟

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

    /// <summary>解析 IP 列表字符串为结构化规则数组</summary>
    public static ParsedIpRule[] ParseIpList(String ipList)
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

    /// <summary>IP 规则类型</summary>
    public enum IpRuleType : byte
    {
        /// <summary>精确匹配</summary>
        Exact,
        /// <summary>CIDR 网段</summary>
        Cidr,
        /// <summary>通配符匹配</summary>
        Wildcard
    }

    /// <summary>解析后的 IP 规则</summary>
    /// <param name="Type">规则类型</param>
    /// <param name="Value">原始值</param>
    /// <param name="ParsedIp">解析后的 IP 地址</param>
    /// <param name="Mask">CIDR 掩码位数</param>
    public readonly record struct ParsedIpRule(IpRuleType Type, String Value, IPAddress? ParsedIp, Int32? Mask);
}
