using System;
using System.Collections;
using System.Runtime.Remoting.Channels;
using System.Runtime.Serialization.Formatters;
using Belikov.GenuineChannels.GenuineTcp;
using Belikov.GenuineChannels.Parameters;
using Zyan.Communication.Protocols;
using Zyan.Communication.Toolbox;
using Zyan.SafeDeserializationHelpers.Channels;

namespace Zyan.Communication.GenuineChannels
{
    /// <summary>
    /// Client protocol setup for bi-directional GenuineTcp communication with support for user defined authentication and security.
    /// </summary>
    public sealed class GenuineTcpClientProtocolSetup : CustomClientProtocolSetup, IClientProtocolSetup
    {
        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning)
            : base((settings, clientSinkChain, serverSinkChain) => new GenuineTcpChannel(settings, clientSinkChain, serverSinkChain))
        {
            _channelName = "GenuineTcpClientProtocolSetup" + Guid.NewGuid().ToString();
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
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        public GenuineTcpClientProtocolSetup()
            : this(Versioning.Strict)
        {
            _channelName = "GenuineTcpClientProtocolSetup" + Guid.NewGuid().ToString();
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpClientProtocolSetup(bool encryption)
            : this()
        {
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning, bool encryption)
            : this(versioning)
        {
            Encryption = encryption;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpClientProtocolSetup(bool encryption, string algorithm)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        public GenuineTcpClientProtocolSetup(bool encryption, string algorithm, int maxAttempts)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, int maxAttempts)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpClientProtocolSetup(bool encryption, string algorithm, bool oaep)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, bool oaep)
            : this(versioning)
        {
            Encryption = encryption;
            Algorithm = algorithm;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpClientProtocolSetup(bool encryption, string algorithm, int maxAttempts, bool oaep)
            : this()
        {
            Encryption = encryption;
            Algorithm = algorithm;
            MaxAttempts = maxAttempts;
            Oaep = oaep;
        }

        /// <summary>
        /// Creates a new instance of the GenuineTcpClientProtocolSetup class.
        /// </summary>
        /// <param name="versioning">Versioning behavior</param>
        /// <param name="encryption">Specifies if the communication sould be encrypted</param>
        /// <param name="algorithm">Symmetric encryption algorithm (e.G. "3DES")</param>
        /// <param name="maxAttempts">Maximum number of connection attempts</param>
        /// <param name="oaep">Specifies if OAEP padding should be activated</param>
        public GenuineTcpClientProtocolSetup(Versioning versioning, bool encryption, string algorithm, int maxAttempts, bool oaep)
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
        public string FormatUrl(string serverAddress, int portNumber, string zyanHostName) =>
            FormatUrlCore(serverAddress, portNumber, zyanHostName);

        /// <summary>
        /// Formats the connection URL for this protocol.
        /// </summary>
        /// <param name="parts">The parts of the url, such as server name, port, etc.</param>
        /// <returns>
        /// Formatted URL supported by the protocol.
        /// </returns>
        string IClientProtocolSetup.FormatUrl(params object[] parts) =>
            FormatUrlCore(parts);

        /// <summary>
        /// Formats the connection URL for this protocol.
        /// </summary>
        /// <param name="parts">The parts of the url, such as server name, port, etc.</param>
        /// <returns>
        /// Formatted URL supported by the protocol.
        /// </returns>
        internal static string FormatUrlCore(params object[] parts)
        {
            if (parts == null || parts.Length < 3)
                throw new ArgumentException("Protocol setup requires three arguments for URL: server address, port number and ZyanHost name.");

            return string.Format("gtcp://{0}:{1}/{2}", parts);
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
            return base.IsUrlValid(url) && url.StartsWith("gtcp");
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

                ConfigureEncryption();
                ConfigureCompression();

                if (_channelFactory == null)
                    throw new ApplicationException("No channel factory specified."); //LanguageResource.ApplicationException_NoChannelFactorySpecified);

                channel = _channelFactory(_channelSettings, BuildClientSinkChain(), BuildServerSinkChain());
                RemotingHelper.ResetCustomErrorsMode();

                var ctx = (channel as GenuineTcpChannel).ITransportContext;
                ctx.IParameterProvider[GenuineParameter.InvocationTimeout] = TimeSpan.FromDays(10);
                ctx.IParameterProvider[GenuineParameter.NoSizeChecking] = true;
            }

            return channel;
        }

        #region Versioning settings

        private Versioning _versioning = Versioning.Strict;

        /// <summary>
        /// Gets or sets the versioning behavior.
        /// </summary>
        public Versioning Versioning => _versioning;

        #endregion
    }
}
