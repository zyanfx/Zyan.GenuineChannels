using System;
using Zyan.Communication.GenuineChannels;
using Zyan.Communication.Protocols;
using Zyan.Communication.Protocols.Tcp;
using Zyan.Communication.Security;

namespace Zyan.Communication
{
    /// <summary>
    /// Helps creating protocols according to the settings.
    /// </summary>
    public static class ProtocolFactory
    {
        /// <summary>
        /// Creates client protocol factory based on the given settings.
        /// </summary>
        /// <param name="name">Channel name as specified in the configuration, i.e.: tcp, tcpex, gtcp, gudp.</param>
        /// <param name="encryption">Whether the encryption is enabled.</param>
        /// <param name="duplex">If channel name is not supplied, this parameter opts it for the duplex channel.</param>
        /// <returns>Client protocol factory.</returns>
        public static Func<ClientProtocolSetup> ClientFactory(string name, bool encryption, bool duplex = true)
        {
            switch (LowerCase(name))
            {
                case "tcpex":
                case "tcpexchannel":
                case "duplex":
                case "tcpduplex":
                case "duplexchannel":
                    return () => new TcpDuplexClientProtocolSetup(encryption: encryption);

                case "":
                case "tcp":
                case "tcpchannel":
                    return duplex ? new Func<ClientProtocolSetup>(
                        () => new TcpDuplexClientProtocolSetup(encryption: encryption)) :
                        () => new TcpCustomClientProtocolSetup(encryption: encryption);

                case "gtcp":
                case "genuine":
                case "genuinechannel":
                case "genuinetcp":
                case "genuinetcpchannel":
                    return () => new GenuineTcpClientProtocolSetup(encryption: encryption);

                case "gudp":
                case "genuineudp":
                case "genuineudpchannel":
                    return () => new GenuineUdpClientProtocolSetup(encryption: encryption);

                default:
                    throw new NotSupportedException("Client protocol not supported: " + name);
            }
        }

        /// <summary>
        /// Creates client protocol setup based on the given settings.
        /// </summary>
        /// <param name="name">Channel name as specified in the configuration, i.e.: tcp, tcpex, gtcp, gudp.</param>
        /// <param name="encryption">Whether the encryption is enabled.</param>
        /// <param name="duplex">If channel name is not supplied, this parameter opts it for the duplex channel.</param>
        /// <returns>Client protocol setup.</returns>
        public static ClientProtocolSetup Client(string name, bool encryption, bool duplex = true) =>
            ClientFactory(name, encryption, duplex)();

        /// <summary>
        /// Creates server protocol factory based on the given settings.
        /// </summary>
        /// <param name="name">Channel name as specified in the configuration, i.e.: tcp, tcpex, gtcp, gudp.</param>
        /// <param name="port">Network port to listen on.</param>
        /// <param name="authProvider">Authentication provider.</param>
        /// <param name="encryption">Whether the encryption is enabled.</param>
        /// <param name="duplex">If channel name is not supplied, this parameter opts it for the duplex channel.</param>
        /// <returns>Server protocol setup.</returns>
        public static ServerProtocolSetup Server(string name, int port, IAuthenticationProvider authProvider, bool encryption, bool duplex = true)
        {
            switch (LowerCase(name))
            {
                case "tcpex":
                case "tcpexchannel":
                case "duplex":
                case "tcpduplex":
                case "duplexchannel":
                    return new TcpDuplexServerProtocolSetup(port, authProvider, encryption: encryption);

                case "tcp":
                case "tcpchannel":
                case "":
                    return duplex ?
                        new TcpDuplexServerProtocolSetup(port, authProvider, encryption: encryption) as ServerProtocolSetup :
                        new TcpCustomServerProtocolSetup(port, authProvider, encryption: encryption);

                case "gtcp":
                case "genuine":
                case "genuinechannel":
                case "genuinetcp":
                case "genuinetcpchannel":
                    return new GenuineTcpServerProtocolSetup(port, authProvider, encryption: encryption);

                case "gudp":
                case "genuineudp":
                case "genuineudpchannel":
                    return new GenuineUdpServerProtocolSetup(port, authProvider, encryption: encryption);

                default:
                    throw new NotSupportedException("Server protocol not supported: " + name);
            }
        }
        internal static string LowerCase(this string text)
        {
            if (string.IsNullOrEmpty(text))
            {
                return string.Empty;
            }

            return text.ToLower();
        }
    }
}
