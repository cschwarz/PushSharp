using System;
using System.Security.Cryptography;

namespace PushSharp.Apple
{
    public class ApnsHttp2Configuration
    {
        #region Constants
        const string APNS_SANDBOX_HOST = "api.development.push.apple.com";
        const string APNS_PRODUCTION_HOST = "api.push.apple.com";

        const uint APNS_SANDBOX_PORT = 443;
        const uint APNS_PRODUCTION_PORT = 443;
        #endregion

        public ApnsHttp2Configuration (string overrideHost, uint overridePort, bool skipSsl = true)
        {
            SkipSsl = skipSsl;

            Initialize (ApnsServerEnvironment.Sandbox, null, null, null);

            OverrideServer (overrideHost, overridePort);
        }

        public ApnsHttp2Configuration (ApnsServerEnvironment serverEnvironment, string teamId, string privateKeyId, string privateKey)
        {
            Initialize (serverEnvironment, teamId, privateKeyId, privateKey);
        }

        void Initialize (ApnsServerEnvironment serverEnvironment, string teamId, string privateKeyId, string privateKey)
        {
            var production = serverEnvironment == ApnsServerEnvironment.Production;

            Host = production ? APNS_PRODUCTION_HOST : APNS_SANDBOX_HOST;
            Port = production ? APNS_PRODUCTION_PORT : APNS_SANDBOX_PORT;
            
            TeamId = teamId;
            PrivateKeyId = privateKeyId;
            PrivateKey = CngKey.Import(Convert.FromBase64String(privateKey), CngKeyBlobFormat.Pkcs8PrivateBlob);

            MillisecondsToWaitBeforeMessageDeclaredSuccess = 3000;
            ConnectionTimeout = 10000;
            MaxConnectionAttempts = 3;

            FeedbackIntervalMinutes = 10;
            FeedbackTimeIsUTC = false;

            KeepAlivePeriod = TimeSpan.FromMinutes (20);
            KeepAliveRetryPeriod = TimeSpan.FromSeconds (30);

            InternalBatchSize = 1000;
            InternalBatchingWaitPeriod = TimeSpan.FromMilliseconds (750);

            InternalBatchFailureRetryCount = 1;
        }

        public void OverrideServer (string host, uint port)
        {
            Host = host;
            Port = port;
        }

        public string Host { get; private set; }

        public uint Port { get; private set; }

        public string TeamId { get; private set; }

        public string PrivateKeyId { get; set; }

        public CngKey PrivateKey { get; private set; }

        public bool SkipSsl { get; set; }

        public int MillisecondsToWaitBeforeMessageDeclaredSuccess { get; set; }

        public int FeedbackIntervalMinutes { get; set; }

        public bool FeedbackTimeIsUTC { get; set; }

        public int ConnectionTimeout { get; set; }

        public int MaxConnectionAttempts { get; set; }

        /// <summary>
        /// The internal connection to APNS servers batches notifications to send before waiting for errors for a short time.
        /// This value will set a maximum size per batch.  The default value is 1000.  You probably do not want this higher than 7500.
        /// </summary>
        /// <value>The size of the internal batch.</value>
        public int InternalBatchSize { get; set; }

        /// <summary>
        /// How long the internal connection to APNS servers should idle while collecting notifications in a batch to send.
        /// Setting this value too low might result in many smaller batches being used.
        /// </summary>
        /// <value>The internal batching wait period.</value>
        public TimeSpan InternalBatchingWaitPeriod { get; set; }

        /// <summary>
        /// How many times the internal batch will retry to send in case of network failure. The default value is 1.
        /// </summary>
        /// <value>The internal batch failure retry count.</value>
        public int InternalBatchFailureRetryCount { get; set; }

        /// <summary>
        /// Gets or sets the keep alive period to set on the APNS socket
        /// </summary>
        public TimeSpan KeepAlivePeriod { get; set; }

        /// <summary>
        /// Gets or sets the keep alive retry period to set on the APNS socket
        /// </summary>
        public TimeSpan KeepAliveRetryPeriod { get; set; }

        public enum ApnsServerEnvironment {
            Sandbox,
            Production
        }
    }
}