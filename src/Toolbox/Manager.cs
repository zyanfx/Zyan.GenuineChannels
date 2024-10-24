/*
 THIS CODE IS BASED ON:
 --------------------------------------------------------------------------------------------------------------
 TcpEx Remoting Channel
 Version 1.2 - 18 November, 2003
 Richard Mason - r.mason@qut.edu.au
 Originally published at GotDotNet:
 http://www.gotdotnet.com/Community/UserSamples/Details.aspx?SampleGuid=3F46C102-9970-48B1-9225-8758C38905B1
 Copyright © 2003 Richard Mason. All Rights Reserved.
 --------------------------------------------------------------------------------------------------------------
*/
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Zyan.Communication.Toolbox;

namespace Zyan.Communication.Protocols.Tcp.DuplexChannel
{
    internal class Manager
    {
        #region Uri Utilities

        public static IPAddress[] GetAddresses()
        {
            return _addresses.Value.ToArray();
        }

        public static string[] GetAddresses(int port, Guid guid, bool includeGuid)
        {
            var addresses = new List<string>();

            if (guid != Guid.Empty && includeGuid)
                addresses.Add(guid.ToString());

            if (port != 0)
                _addresses.Value.ForEach(addr => addresses.Add(String.Format("{0}:{1}", addr, port)));

            return addresses.Distinct().ToArray();
        }

        private static Lazy<List<IPAddress>> _addresses = new Lazy<List<IPAddress>>(() =>
        {
            // get loopback address
            var addressFamily = DefaultAddressFamily;
            var loopback = addressFamily == AddressFamily.InterNetwork ? IPAddress.Loopback : IPAddress.IPv6Loopback;
            List<IPAddress> addresses;

            try
            {
                // GetAllNetworkInterfaces() may be slow, so execute it once and cache results
                var query =
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where nic.OperationalStatus == OperationalStatus.Up
                    let props = nic.GetIPProperties()
                    where props.GatewayAddresses.Any() // has default gateway address
                    from ua in GetUnicastAddresses(props)
                    where ua.AddressFamily == addressFamily
                    select ua;
                addresses = query.ToList();
            }
            catch
            {
                // GetAllNetworkInterfaces might fail on Linux and will fail on Android due to this bug:
                // https://bugzilla.xamarin.com/show_bug.cgi?id=1969
                addresses = Dns.GetHostAddresses(Dns.GetHostName()).ToList();
            }

            // Mono framework doesn't include loopback address
            if (!addresses.Contains(loopback))
                addresses.Add(loopback);

            return addresses;

        }, true);

        private static IEnumerable<IPAddress> GetUnicastAddresses(IPInterfaceProperties ipProps)
        {
            // straightforward version (may throw exceptions on Mono 2.10.x/Windows)
            if (!MonoCheck.IsRunningOnMono || MonoCheck.IsUnixOS)
            {
                return ipProps.UnicastAddresses.Select(address => address.Address);
            }

            var result = new List<IPAddress>();

            // catch exceptions to work around Mono 2.10.x bug with some virtual network adapter drivers
            // http://bugzilla.xamarin.com/show_bug.cgi?id=1254
            try
            {
                foreach (var address in ipProps.UnicastAddresses)
                {
                    try
                    {
                        result.Add(address.Address);
                    }
                    catch // NullReferenceException
                    {
                    }
                }
            }
            catch // NullReferenceException
            {
            }

            return result;
        }

        #endregion

        #region DefaultAddressFamily

        private static AddressFamily DefaultAddressFamily
        {
            // prefer IPv4 address
            get { return OSSupportsIPv4 ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6; }
        }

        private static bool? osSupportsIPv4;

        /// <summary>
        /// Gets a value indicating whether IPv4 support is available and enabled on the current host.
        /// </summary>
        /// <remarks>
        /// This property is equivalent to Socket.OSSupportsIPv4 (which is not available under Mono and FX3.5).
        /// </remarks>
        public static bool OSSupportsIPv4
        {
            get
            {
                CheckProtocolSupport();
                return osSupportsIPv4.Value;
            }
        }

        private static void CheckProtocolSupport()
        {
            if (osSupportsIPv4 == null)
            {
                try
                {
                    using (var tmpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
                    {
                        osSupportsIPv4 = true;
                    }
                }
                catch
                {
                    osSupportsIPv4 = false;
                }
            }
        }

        #endregion
    }
}
