using MatthiWare.CommandLine;

namespace sniffer;

public class Program
{
    private static void Main(string[] args)
    {
        var parser = new CommandLineParser<CatchingOptions>();
        var result = parser.Parse(args);

        // Enter checking
        if (result.HasErrors)
        {
            Console.Error.WriteLine("Incorrect input.");
            return;
        }

        var startingOptions = result.Result;

        // Parametr checking
        if (!ParamValidator.Validator(startingOptions))
        {
            Console.WriteLine("incorrect params");
            return;
        }
        

        var capturer = new Capturer(startingOptions);
        capturer.CatchPacket();
    }
}