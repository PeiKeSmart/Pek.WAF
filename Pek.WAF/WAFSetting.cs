using System.ComponentModel;

using NewLife.Configuration;

namespace Pek.WAF;

/// <summary>WAF防火墙配置</summary>
[Config("WAF")]
public class WAFSetting : Config<WAFSetting>
{
    /// <summary>防火墙规则</summary>
    [Description("防火墙规则")]
    public Rule? Ruleset { get; set; }
}
