using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PushSharp.Apple
{
    public class ApnsHttp2Connection
    {
        static int ID = 0;

        public ApnsHttp2Connection(ApnsHttp2Configuration configuration)
        {
            id = ++ID;
            if (id >= int.MaxValue)
                ID = 0;

            Configuration = configuration;

            httpClient = new HttpClient(new WinHttpHandler() { SslProtocols = SslProtocols.Tls12 });
        }

        public ApnsHttp2Configuration Configuration { get; private set; }

        int id = 0;
        HttpClient httpClient;

        public async Task Send(ApnsHttp2Notification notification)
        {            
            var url = string.Format("https://{0}:{1}/3/device/{2}",
                          Configuration.Host,
                          Configuration.Port,
                          notification.DeviceToken);
            var uri = new Uri(url);

            var payload = notification.Payload.ToString();

            StringContent content = new StringContent(payload);

            content.Headers.Add("Authorization", string.Concat("Bearer ", CreateJwtToken()));

            content.Headers.Add("apns-id", notification.Uuid); // UUID            

            if (notification.Expiration.HasValue)
            {
                var sinceEpoch = notification.Expiration.Value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                var secondsSinceEpoch = (long)sinceEpoch.TotalSeconds;
                content.Headers.Add("apns-expiration", secondsSinceEpoch.ToString()); //Epoch in seconds
            }

            if (notification.Priority.HasValue)
            {
                content.Headers.Add("apns-priority", notification.Priority == ApnsPriority.Low ? "5" : "10"); // 5 or 10
                content.Headers.Add("apns-push-type", notification.Priority == ApnsPriority.Low ? "background" : "alert"); // 5 or 10
            }

            content.Headers.Add("content-length", payload.Length.ToString());

            if (!string.IsNullOrEmpty(notification.Topic))
                content.Headers.Add("apns-topic", notification.Topic); // string topic

            var response = await httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Post, uri) { Content = content, Version = new Version(2, 0) });

            if (response.IsSuccessStatusCode)
            {
                // Check for matching uuid's
                var responseUuid = response.Headers.GetValues("apns-id").FirstOrDefault();
                if (responseUuid != notification.Uuid)
                    throw new Exception("Mismatched APNS-ID header values");
            }
            else
            {
                // Try parsing json body
                var json = new JObject();

                if (response.Content != null)
                {
                    var body = await response.Content.ReadAsStringAsync();
                    json = JObject.Parse(body);
                }

                if (response.StatusCode == HttpStatusCode.Gone)
                {

                    var timestamp = DateTime.UtcNow;
                    if (json != null && json["timestamp"] != null)
                    {
                        var sinceEpoch = json.Value<long>("timestamp");
                        timestamp = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc).AddSeconds(sinceEpoch);
                    }

                    // Expired
                    throw new Core.DeviceSubscriptionExpiredException(notification)
                    {
                        OldSubscriptionId = notification.DeviceToken,
                        NewSubscriptionId = null,
                        ExpiredAt = timestamp
                    };
                }

                // Get the reason
                var reasonStr = json.Value<string>("reason");

                throw new Core.NotificationException(reasonStr, notification);
            }
        }

        private string CreateJwtToken()
        {
            var header = JsonConvert.SerializeObject(new { alg = "ES256", kid = Configuration.PrivateKeyId });
            var payload = JsonConvert.SerializeObject(new { iss = Configuration.TeamId, iat = ToEpoch() });

            using (var dsa = new ECDsaCng(Configuration.PrivateKey))
            {
                dsa.HashAlgorithm = CngAlgorithm.Sha256;
                var headerBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(header));
                var payloadBasae64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(payload));
                var unsignedJwtData = $"{headerBase64}.{payloadBasae64}";
                var signature = dsa.SignData(Encoding.UTF8.GetBytes(unsignedJwtData));
                return $"{unsignedJwtData}.{Convert.ToBase64String(signature)}";
            }
        }

        private static int ToEpoch()
        {
            var currentHour = new DateTime(DateTime.Now.Year, DateTime.Now.Month, DateTime.Now.Day, DateTime.Now.Hour, 0, 0).ToUniversalTime();
            return Convert.ToInt32((currentHour - new DateTime(1970, 1, 1)).TotalSeconds);
        }
    }
}