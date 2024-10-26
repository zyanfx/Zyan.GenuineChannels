using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Channels;
using System.Runtime.Serialization.Formatters;
using Belikov.GenuineChannels.GenuineTcp;
using Zyan.Communication.ChannelSinks.ClientAddress;
using Zyan.Communication.Protocols;
using Zyan.Communication.Security;
using Zyan.Communication.Toolbox;
using Zyan.SafeDeserializationHelpers.Channels;
using Manager = Zyan.Communication.Protocols.Tcp.DuplexChannel.Manager;

namespace Zyan.Communication.GenuineChannels
{
    /// <summary>
    /// Server protocol setup for bi-directional GenuineTcp communication with support for user defined authentication and security.
    /// </summary>
    public sealed class GenuineTcpServerProtocolSetup : CustomServerProtocolSetup
    {
        private int _tcpPort = 0;
        private string _ipAddress = "0.0.0.0";

        /// <summary>
        /// Gets or sets the TCP port to listen for client calls.
        /// </summary>
        public int TcpPort
        {
            get { return _tcpPort; }
            set
            {
                if (_tcpPort < 0 || _tcpPort > 65535)
                    throw new ArgumentOutOfRangeException("tcpPort", "Invalid TCP port."); //LanguageResource.ArgumentOutOfRangeException_InvalidTcpPortRange);

                _tcpPort = value;
            }
        }

        /// <summary>
        /// Gets or sets the IP Address to listen for client calls.
        /// </summary>
        public string IpAddress
        {
            get { return _ipAddress; }
            set { _ipAddress = value; }
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning)
            : base((settings, clientSinkChain, serverSinkChain) => new GenuineTcpChannel(settings, clientSinkChain, serverSinkChain))
        {
            _versioning = versioning;

            var formatterSettings = new Hashtable
            {
                { "includeVersions", _versioning == Versioning.Strict },
                { "strictBinding", _versioning == Versioning.Strict }
            };

            ClientSinkChain.Add(new SafeBinaryClientFormatterSinkProvider(formatterSettings, null));
            ServerSinkChain.Add(new SafeBinaryServerFormatterSinkProvider(formatterSettings, null) { TypeFilterLevel = TypeFilterLevel.Full });
            ServerSinkChain.Add(new ClientAddressServerChannelSinkProvider());
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        public GenuineTcpServerProtocolSetup()
            : this(Versioning.Strict)
        { }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        public GenuineTcpServerProtocolSetup(int tcpPort)
            : this()
        {
            TcpPort = tcpPort;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        public GenuineTcpServerProtocolSetup(string ipAddress, int tcpPort)
            : this()
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        public GenuineTcpServerProtocolSetup(int tcpPort, IAuthenticationProvider authProvider)
            : this()
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        public GenuineTcpServerProtocolSetup(string ipAddress, int tcpPort, IAuthenticationProvider authProvider)
            : this()
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, int tcpPort, IAuthenticationProvider authProvider)
            : this(versioning)
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
        }
        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, string ipAddress, int tcpPort, IAuthenticationProvider authProvider)
            : this(versioning)
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpServerProtocolSetup(int tcpPort, IAuthenticationProvider authProvider, bool encryption)
            : this()
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpServerProtocolSetup(string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption)
            : this()
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, int tcpPort, IAuthenticationProvider authProvider, bool encryption)
            : this(versioning)
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption)
            : this(versioning)
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpServerProtocolSetup(int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm)
            : this()
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpServerProtocolSetup(string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm)
            : this()
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm)
            : this(versioning)
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm)
            : this(versioning)
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpServerProtocolSetup(int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm, bool oaep)
            : this()
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpServerProtocolSetup(string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm, bool oaep)
            : this()
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm, bool oaep)
            : this(versioning)
        {
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpServerProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="ipAddress">IP address to bind</param>
        /// <param name="tcpPort">TCP port number</param>
        /// <param name="authProvider">Authentication provider</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpServerProtocolSetup(Versioning versioning, string ipAddress, int tcpPort, IAuthenticationProvider authProvider, bool encryption, string algorithm, bool oaep)
            : this(versioning)
        {
            IpAddress = ipAddress;
            TcpPort = tcpPort;
            AuthenticationProvider = authProvider;
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates and configures a Remoting channel.
        /// </summary>
        /// <returns>Remoting channel</returns>
        public override IChannel CreateChannel()
        {
            var channel = ChannelServices.GetChannel(_channelName);

            if (channel == null)
            {
                _channelSettings["name"] = _channelName;
                _channelSettings["port"] = _tcpPort;
                _channelSettings["interface"] = _ipAddress;
                _channelSettings["typeFilterLevel"] = TypeFilterLevel.Full;
                _channelSettings["InvocationTimeout"] = TimeSpan.FromDays(10);
                _channelSettings["ConnectTimeout"] = TimeSpan.FromDays(10);

                ConfigureEncryption();
                ConfigureCompression();

                if (_channelFactory == null)
                    throw new ApplicationException("No channel factory specified."); //LanguageResource.ApplicationException_NoChannelFactorySpecified);

                channel = _channelFactory(_channelSettings, BuildClientSinkChain(), BuildServerSinkChain());
                RemotingHelper.ResetCustomErrorsMode();
            }

            return channel;
        }

        // Get addresses from local network adaptors
        private static Lazy<HashSet<string>> LocalAddresses = new Lazy<HashSet<string>>(() =>
            new HashSet<string>(Manager.GetAddresses().Select(id => id.ToString())));

        /// <summary>
        /// Determines whether the given URL is discoverable across the network.
        /// </summary>
        /// <param name="url">The URL to check.</param>
        protected override bool IsDiscoverableUrl(string url)
        {
            if (!base.IsDiscoverableUrl(url))
            {
                return false;
            }

            // URL based on ChannelID is not discoverable
            var hostAddress = new Uri(url).Host;
            return LocalAddresses.Value.Contains(hostAddress);
        }

        #region Versioning settings

        private Versioning _versioning = Versioning.Strict;

        /// <summary>
        /// Gets or sets the versioning behavior.
        /// </summary>
        private Versioning Versioning
        {
            get { return _versioning; }
        }

        #endregion
    }
}
