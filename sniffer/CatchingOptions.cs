using MatthiWare.CommandLine.Core.Attributes;

namespace sniffer;

public class CatchingOptions
{
    [Required]
    [Name("pr", "protocol ( Required tcp or udp ))")]
    [Description("catching protocol")]
    public string Protocol { get; set; }

    [Name("sp", "sourceport")]
    [Description("source port")]
    [DefaultValue(-1)]
    public int SourcePort { get; set; }

    [Name("dp", "destport")]
    [Description("destination port")]
    [DefaultValue(-1)]
    public int DestinationPort { get; set; }

    [Name("sip", "sourceip")]
    [Description("source ip")]
    [DefaultValue(null)]
    public string SourceIP { get; set; }

    [Name("dip", "destip")]
    [Description("destination ip")]
    [DefaultValue(null)]
    public string DestinationIP { get; set; }
}