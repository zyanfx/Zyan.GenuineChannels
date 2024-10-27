using System;
using System.Collections;
using System.Runtime.Remoting.Channels;
using System.Runtime.Serialization.Formatters;
using Belikov.GenuineChannels.GenuineTcp;
using Belikov.GenuineChannels.GenuineUdp;
using Belikov.GenuineChannels.Parameters;
using Zyan.Communication.Protocols;
using Zyan.Communication.Toolbox;
using Zyan.SafeDeserializationHelpers.Channels;

namespace Zyan.Communication.GenuineChannels
{
    /// <summary>
    /// Client protocol setup for bi-directional GenuineUdp communication with support for user defined authentication and security.
    /// </summary>
    public sealed class GenuineUdpClientProtocolSetup : CustomClientProtocolSetup, IClientProtocolSetup
    {
        private string _ipAddress = "0.0.0.0";

        /// <summary>
        /// Gets or sets the IP Address to listen for client calls.
        /// </summary>
        public string IpAddress
        {
            get { return _ipAddress; }
            set { _ipAddress = value; }
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning)
            : base((settings, clientSinkChain, serverSinkChain) => new GenuineUdpChannel(settings, clientSinkChain, serverSinkChain))
        {
            _channelName = "GenuineUdpClientProtocolSetup" + Guid.NewGuid().ToString();
            _versioning = versioning;

            var formatterSettings = new Hashtable
            {
                { "includeVersions", _versioning == Versioning.Strict },
                { "strictBinding", _versioning == Versioning.Strict }
            };

            ClientSinkChain.Add(new SafeBinaryClientFormatterSinkProvider(formatterSettings, null));
            ServerSinkChain.Add(new SafeBinaryServerFormatterSinkProvider(formatterSettings, null) { TypeFilterLevel = TypeFilterLevel.Full });
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        public GenuineUdpClientProtocolSetup()
            : this(Versioning.Strict)
        {
            _channelName = "GenuineUdpClientProtocolSetup" + Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineUdpClientProtocolSetup(bool encryption)
            : this()
        {
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning, bool encryption)
            : this(versioning)
        {
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        public GenuineUdpClientProtocolSetup(bool encryption, string algorithm)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        public GenuineUdpClientProtocolSetup(bool encryption, string algorithm, int maxAttempts)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, int maxAttempts)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineUdpClientProtocolSetup(bool encryption, string algorithm, bool oaep)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, bool oaep)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineUdpClientProtocolSetup(bool encryption, string algorithm, int maxAttempts, bool oaep)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineUdpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineUdpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, int maxAttempts, bool oaep)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
            Oaep = oaep;
        }

        /// <summary>
        /// Formats the connection URL for this protocol.
        /// </summary>
        /// <param name="serverAddress">The server address.</param>
        /// <param name="portNumber">The port number.</param>
        /// <param name="zyanHostName">Name of the zyan host.</param>
        /// <returns>
        /// Formatted URL supported by the protocol.
        /// </returns>
        public string FormatUrl(string serverAddress, int portNumber, string zyanHostName)
        {
            return (this as IClientProtocolSetup).FormatUrl(serverAddress, portNumber, zyanHostName);
        }

        /// <summary>
        /// Formats the connection URL for this protocol.
        /// </summary>
        /// <param name="parts">The parts of the url, such as server name, port, etc.</param>
        /// <returns>
        /// Formatted URL supported by the protocol.
        /// </returns>
        string IClientProtocolSetup.FormatUrl(params object[] parts)
        {
            if (parts == null || parts.Length < 3)
                throw new ArgumentException(GetType().Name + " requires three arguments for URL: server address, port number and ZyanHost name.");

            return string.Format("gudp://{0}:{1}/{2}", parts);
        }

        /// <summary>
        /// Checks whether the given URL is valid for this protocol.
        /// </summary>
        /// <param name="url">The URL to check.</param>
        /// <returns>
        /// True, if the URL is supported by the protocol, otherwise, False.
        /// </returns>
        public override bool IsUrlValid(string url)
        {
            return base.IsUrlValid(url) && url.StartsWith("gudp");
        }

        /// <summary>
        /// Creates and configures a Remoting channel.
        /// </summary>
        /// <returns>Remoting channel</returns>
        public override IChannel CreateChannel()
        {
            IChannel channel = ChannelServices.GetChannel(_channelName);

            if (channel == null)
            {
                _channelSettings["name"] = _channelName;
                _channelSettings["port"] = 0;
                _channelSettings["typeFilterLevel"] = TypeFilterLevel.Full;

                // the channel requires Address specified as gudp://0.0.0.0
                if (!string.IsNullOrWhiteSpace(_ipAddress))
                {
                    _channelSettings["Address"] =
                        _ipAddress.StartsWith("gudp://", StringComparison.OrdinalIgnoreCase) ?
                        _ipAddress : "gudp://" + _ipAddress;
                }

                ConfigureEncryption();
                ConfigureCompression();

                if (_channelFactory == null)
                    throw new ApplicationException("No channel factory specified."); //LanguageResource.ApplicationException_NoChannelFactorySpecified);

                channel = _channelFactory(_channelSettings, BuildClientSinkChain(), BuildServerSinkChain());
                RemotingHelper.ResetCustomErrorsMode();

                var ctx = (channel as GenuineUdpChannel).ITransportContext;
                ctx.IParameterProvider[GenuineParameter.InvocationTimeout] = TimeSpan.FromDays(10);
            }

            return channel;
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
