using System.Net;

namespace sniffer;

public class ParamValidator
{
    public static bool Validator(CatchingOptions options)
    {
        if (!(options.Protocol.ToLower() == "tcp" || options.Protocol.ToLower() == "udp")) return false;

        // -1 - Port didn't chosen
        if (options.DestinationPort > 65535 || options.DestinationPort < -1) return false;

        if (options.SourcePort > 65535 || options.SourcePort < -1) return false;

        // null - IP not specified
        if (options.DestinationIP != null)
            if (!IsIPAddress(options.DestinationIP))
                return false;

        if (options.SourceIP != null)
            if (!IsIPAddress(options.SourceIP))
                return false;

        return true;
    }

    private static bool IsIPAddress(string ipAddress)
    {
        var isIPAddres = false;

        try
        {
            IPAddress address;
            isIPAddres = IPAddress.TryParse(ipAddress, out address);
        }
        catch (Exception e)
        {
        }

        return isIPAddres;
    }
}