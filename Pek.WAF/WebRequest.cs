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
}
