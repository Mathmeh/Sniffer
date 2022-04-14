using System.Runtime.CompilerServices;
using PacketDotNet;
using SharpPcap;

namespace sniffer;

public class Capturer
{
        private CatchingOptions Options;
        
        public Capturer(CatchingOptions options)
        {
            Options = options;
        }
       
        public void CatchPacket()
        {
            if (!DeviceChecker())
            {
                return;
            };
            
            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            
            // Device`s number correct check
            if (!int.TryParse(Console.ReadLine(), out int i))
            {
                Console.WriteLine("incorrect device");
                return;
            }    
            
            int readTimeoutMilliseconds = 1000;
            
            using var device1 = CaptureDeviceList.Instance[i];
            

            // Register our handler function to the 'packet arrival' event
            device1.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);
           

            // Open the devices for capturing
            device1.Open(DeviceModes.Promiscuous, readTimeoutMilliseconds);

            device1.Filter = FilterCreator();

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, hit 'Enter' to stop...",
                device1.Name, device1.Description);

            // Start the capturing process
            device1.StartCapture();

            // Wait for 'Enter' from the user.
            Console.ReadLine();

            // Stop the capturing process
            device1.StopCapture();
            Console.WriteLine("-- Capture stopped.");

            // Print out the device statistics
            Console.WriteLine("device1 {0}", device1.Statistics.ToString());
        }

    
        private  void device_OnPacketArrival(object sender, PacketCapture e)
        {
            var time = e.Header.Timeval.Date;
            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
           var  size=packet.PayloadPacket.Bytes.Length;
            
            if (Options.Protocol == "tcp")
            {
                var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
                if (tcpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                    System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                    System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                    int srcPort = tcpPacket.SourcePort;
                    int dstPort = tcpPacket.DestinationPort;


                    Console.WriteLine("{0}:{1}:{2},{3}   {4}:{5} -> {6}:{7}, Size={8} bytes, Protocol={9}",
                        time.Hour, time.Minute, time.Second, time.Millisecond,
                        srcIp, srcPort, dstIp, dstPort, size, Options.Protocol);
                }
            }

            if (Options.Protocol == "udp")
            {
                var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();
                if (udpPacket != null)
                {
                    var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                    System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                    System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                    int srcPort = udpPacket.SourcePort;
                    int dstPort = udpPacket.DestinationPort;


                    Console.WriteLine("{0}:{1}:{2},{3}   {4}:{5} -> {6}:{7}, Size={8} bytes, Protocol={9}",
                        time.Hour, time.Minute, time.Second, time.Millisecond,
                        srcIp, srcPort, dstIp, dstPort, size, Options.Protocol);
                }
            }
        }
        
        private static bool DeviceChecker()
        {
            if (CaptureDeviceList.Instance.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return false;
            }

            Console.WriteLine();
            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            // вывод доступных девайсов
            int i = 0;
            foreach (var dev in CaptureDeviceList.Instance)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            return true;
        }

        private   string FilterCreator()
        {
            string filter = "";
            
            filter += Options.Protocol;

            if (Options.DestinationPort != -1)
            {
                filter += " and dst port " + Options.DestinationPort.ToString();
            }

            if (Options.SourcePort != -1)
            {
                filter += " and src port " + Options.SourcePort.ToString();
            }

            if (Options.DestinationIP != null)
            {
                filter += " and dst net " + Options.DestinationIP;
            }

            if (Options.SourceIP != null)
            {
                filter += " and src net " + Options.SourceIP;
            }

            return filter;
        }

}