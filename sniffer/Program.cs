using System;
using MatthiWare.CommandLine;
using SharpPcap;
using sniffer;

namespace sniffer
{
    public class Program
    {
        static void Main(string[] args)
        {
            var parser = new CommandLineParser<CatchingOptions>();
            var result = parser.Parse(args);
            
            // проверка ввода
            if (result.HasErrors)
            {
                Console.Error.WriteLine("Incorrect input.");
                return;
            }
            
            var startingOptions = result.Result;
            
            // проверка параметров
            if (!ParamValidator.Validator(startingOptions))
            {
                Console.WriteLine("incorrect params");
                return;
            }
            
            Console.WriteLine(startingOptions.Protocol);
            Console.WriteLine(startingOptions.DestinationPort);
            Console.WriteLine(startingOptions.SourcePort);
            Console.WriteLine(startingOptions.DestinationIP);

            var capturer = new Capturer(startingOptions);
            capturer.CatchPacket();
            
            

        }
    }
}