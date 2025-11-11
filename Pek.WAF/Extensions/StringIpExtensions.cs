using System.Net;
using System.Net.Sockets;

using NewLife.Log;

using Pek.Configs;

namespace Pek.WAF.Extensions;

/// <summary>String类型的IP相关扩展方法，用于WAF规则引擎</summary>
public static class StringIpExtensions
{
    /// <summary>检查IP字符串是否在指定的IP列表中</summary>
    /// <param name="remoteIp">要检查的IP地址字符串</param>
    /// <param name="ipList">IP列表字符串，支持多种格式：
    /// - 精确匹配: 192.168.1.100
    /// - CIDR格式: 192.168.1.0/24
    /// - 通配符: 192.168.*.* 或 10.0.1.*
    /// - 多个IP用逗号或分号分隔: 192.168.1.1, 192.168.1.2; 10.0.0.1
    /// </param>
    /// <returns>如果IP在列表中返回true，否则返回false</returns>
    public static Boolean IsInIpList(this String? remoteIp, String ipList)
    {
        // 根据 PekSysSetting.Current.AllowRequestParams 或日志级别判断是否输出详细日志
        var allowDetailLog = PekSysSetting.Current.AllowRequestParams || XTrace.Log.Level <= NewLife.Log.LogLevel.Debug;

        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:开始检查 - RemoteIP:'{remoteIp}', IPList:'{ipList}'");
        }

        if (String.IsNullOrWhiteSpace(remoteIp) || String.IsNullOrWhiteSpace(ipList))
        {
            if (allowDetailLog)
            {
                XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:参数为空 - RemoteIP IsNull:{String.IsNullOrWhiteSpace(remoteIp)}, IPList IsNull:{String.IsNullOrWhiteSpace(ipList)}");
            }
            return false;
        }

        if (!IPAddress.TryParse(remoteIp, out var remoteIpAddress))
        {
            if (allowDetailLog)
            {
                XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:IP解析失败 - RemoteIP:'{remoteIp}' 不是有效的IP地址");
            }
            return false;
        }

        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:IP解析成功 - RemoteIP:'{remoteIp}', AddressFamily:{remoteIpAddress.AddressFamily}");
        }

        var ipEntries = ipList.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:分割IP列表 - 规则数量:{ipEntries.Length}");
        }

        foreach (var entry in ipEntries)
        {
            if (String.IsNullOrEmpty(entry))
                continue;

            // CIDR 格式
            var slashIdx = entry.IndexOf('/');
            if (slashIdx > 0 && slashIdx < entry.Length - 1)
            {
                if (Int32.TryParse(entry.AsSpan(slashIdx + 1), out var mask) && 
                    IPAddress.TryParse(entry.AsSpan(0, slashIdx), out var networkIp))
                {
                    var matched = IsInSubnet(remoteIpAddress, networkIp, mask);
                    if (allowDetailLog)
                    {
                        XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:CIDR检查 - RemoteIP:'{remoteIp}', 规则:'{entry}', 匹配:{matched}");
                    }
                    if (matched)
                        return true;
                }
                continue;
            }

            // 通配符格式
            if (entry.IndexOf('*') >= 0)
            {
                var matched = MatchWildcardIp(remoteIp.AsSpan(), entry.AsSpan());
                if (allowDetailLog)
                {
                    XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:通配符检查 - RemoteIP:'{remoteIp}', 规则:'{entry}', 匹配:{matched}");
                }
                if (matched)
                    return true;
                continue;
            }

            // 精确匹配
            var exactMatch = String.Equals(remoteIp, entry, StringComparison.Ordinal);
            if (allowDetailLog)
            {
                XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:精确匹配 - RemoteIP:'{remoteIp}', 规则:'{entry}', 匹配:{exactMatch}");
            }
            if (exactMatch)
                return true;
        }

        if (allowDetailLog)
        {
            XTrace.Log.Debug($"[StringIpExtensions.IsInIpList]:所有规则检查完毕 - RemoteIP:'{remoteIp}' 未匹配任何规则，返回 false");
        }

        return false;
    }

    /// <summary>检查IP字符串是否不在指定的IP列表中（白名单模式）</summary>
    /// <param name="remoteIp">要检查的IP地址字符串</param>
    /// <param name="ipList">IP列表字符串，格式同IsInIpList</param>
    /// <returns>如果IP不在列表中返回true，否则返回false</returns>
    public static Boolean IsNotInIpList(this String? remoteIp, String ipList) => !IsInIpList(remoteIp, ipList);

    private static Boolean IsInSubnet(IPAddress remoteIp, IPAddress networkIp, Int32 mask)
    {
#if NET8_0_OR_GREATER
        var network = new System.Net.IPNetwork(networkIp, mask);
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

    private static Boolean MatchWildcardIp(ReadOnlySpan<Char> ip, ReadOnlySpan<Char> pattern)
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
}
