using System.Net;

using Microsoft.Net.Http.Headers;

using NewLife.Caching;

#if NET8_0_OR_GREATER
using IPNetwork = System.Net.IPNetwork;
#endif

namespace Pek.WAF;

public record WebRequest(HttpRequest request, ICacheProvider cacheProvider)
{
    public String? Method => request.Method;

    public String? Path => request.Path.Value;

    public String? QueryString => request.QueryString.Value;

    public String? Referer => request.Headers[HeaderNames.Referer].ToString();

    public String? UserAgent => request.Headers[HeaderNames.UserAgent].ToString();

    public String? RemoteIp => request.HttpContext.Connection.RemoteIpAddress?.ToString();

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
#if NET8_0_OR_GREATER
        var network = new IPNetwork(IPAddress.Parse(ip), mask);
        return network.Contains(request.HttpContext.Connection.RemoteIpAddress!);
#elif NET6_0 || NET7_0
        var ipAddress = IPAddress.Parse(ip);
        var remoteIpAddress = request.HttpContext.Connection.RemoteIpAddress;

        if (remoteIpAddress == null)
        {
            return false;
        }

        var ipBytes = ipAddress.GetAddressBytes();
        var remoteIpBytes = remoteIpAddress.GetAddressBytes();
        var maskBytes = BitConverter.GetBytes(~((1 << (32 - mask)) - 1));

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(maskBytes);
        }

        for (var i = 0; i < ipBytes.Length; i++)
        {
            if ((ipBytes[i] & maskBytes[i]) != (remoteIpBytes[i] & maskBytes[i]))
            {
                return false;
            }
        }

        return true;
#endif
    }

    public Boolean IpInFile(String path)
    {
        var keyname = System.IO.Path.GetFileNameWithoutExtension(path);

        var data = cacheProvider.Cache.Get<IEnumerable<String>>(keyname);
        if (data == null && File.Exists(path))
        {
            data = File.ReadAllLines(path);
            cacheProvider.Cache.Set<IEnumerable<String>>(keyname, File.ReadAllLines(path), 15 * 60);
        }

        return data?.Contains(RemoteIp, StringComparer.OrdinalIgnoreCase) ?? false;
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
        if (String.IsNullOrWhiteSpace(ipList) || String.IsNullOrWhiteSpace(RemoteIp))
            return false;

        var remoteIpAddress = request.HttpContext.Connection.RemoteIpAddress;
        if (remoteIpAddress == null)
            return false;

        // 分割IP列表（支持逗号和分号）
        var ipEntries = ipList.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var ipEntry in ipEntries)
        {
            var entry = ipEntry.Trim();
            if (String.IsNullOrEmpty(entry))
                continue;

            // 1. CIDR 格式检查 (例如: 192.168.1.0/24)
            if (entry.Contains('/'))
            {
                var parts = entry.Split('/');
                if (parts.Length == 2 && Int32.TryParse(parts[1], out var mask))
                {
                    try
                    {
                        if (InSubnet(parts[0], mask))
                            return true;
                    }
                    catch
                    {
                        // 忽略无效的CIDR格式
                    }
                }
                continue;
            }

            // 2. 通配符格式检查 (例如: 192.168.*.* 或 10.0.1.*)
            if (entry.Contains('*'))
            {
                if (MatchWildcardIp(RemoteIp, entry))
                    return true;
                continue;
            }

            // 3. 精确匹配
            if (String.Equals(RemoteIp, entry, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>检查当前请求的远程IP是否不在指定的IP列表中（白名单模式）</summary>
    /// <param name="ipList">IP列表字符串，格式同IsInIpList</param>
    /// <returns>如果IP不在列表中返回true，否则返回false</returns>
    public Boolean IsNotInIpList(String ipList) => !IsInIpList(ipList);

    private Boolean MatchWildcardIp(String ip, String pattern)
    {
        var ipParts = ip.Split('.');
        var patternParts = pattern.Split('.');

        if (ipParts.Length != 4 || patternParts.Length != 4)
            return false;

        for (var i = 0; i < 4; i++)
        {
            if (patternParts[i] == "*")
                continue;

            if (!String.Equals(ipParts[i], patternParts[i], StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }
}
