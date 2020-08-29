using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace DotNetCoreAwsSignature.Library
{
    /// <summary>
    /// AWS 署名バージョン4 のリクエストを扱うクラスです
    /// </summary>
    public class AwsRequestSigner
    {
        private readonly string accessKey;
        private readonly string secretKey;
        private readonly SHA256 sha256;
        private readonly string algorithm = "AWS4-HMAC-SHA256";

        public AwsRequestSigner(string accessKey, string secretKey)
        {
            if (string.IsNullOrEmpty(accessKey)) throw new ArgumentOutOfRangeException(nameof(accessKey));
            if (string.IsNullOrEmpty(secretKey)) throw new ArgumentOutOfRangeException(nameof(secretKey));

            this.accessKey = accessKey;
            this.secretKey = secretKey;
            sha256 = SHA256.Create();
        }

        /// <summary>
        /// リクエストに対して署名を行います
        /// </summary>
        /// <param name="request"></param>
        /// <param name="service"></param>
        /// <param name="region"></param>
        /// <returns></returns>
        public async Task Sign(HttpRequestMessage request, string service, string region)
        {
            if (string.IsNullOrEmpty(service)) throw new ArgumentOutOfRangeException(nameof(service));
            if (string.IsNullOrEmpty(region)) throw new ArgumentOutOfRangeException(nameof(region));
            if (request == null) throw new ArgumentNullException(nameof(request));

            // --------------------------------------------------------------------------
            // タスク1: 正規化リクエストを作成します
            // --------------------------------------------------------------------------
            var utcNow = DateTimeOffset.UtcNow;
            var (canonicalRequest, amzDate, signedHeaders) = await CreateCanonicalRequest(request, utcNow);

            // --------------------------------------------------------------------------
            // タスク2: 署名対象文字列を作成します
            // --------------------------------------------------------------------------
            var dateStamp = utcNow.ToString("yyyyMMdd");
            var credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
            var stringToSign = $"{algorithm}\n{amzDate}\n{credentialScope}\n" + Hash(Encoding.UTF8.GetBytes(canonicalRequest));

            // --------------------------------------------------------------------------
            // タスク3: 署名を計算します
            // --------------------------------------------------------------------------
            var signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
            var signature = ToHexString(HmacSha256(signingKey, stringToSign));

            // --------------------------------------------------------------------------
            // タスク4: HTTPヘッダに署名を追加します
            // --------------------------------------------------------------------------
            request.Headers.TryAddWithoutValidation("Authorization", $"{algorithm} Credential={accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}");
        }

        /// <summary>
        /// 正規化リクエストを作成します
        /// </summary>
        /// <param name="request"></param>
        /// <param name="utcNow"></param>
        /// <returns>正規化リクエスト、x-amz-dateヘッダの値、署名付きヘッダ のタプル</returns>
        private async Task<(string, string, string)> CreateCanonicalRequest(HttpRequestMessage request, DateTimeOffset utcNow)
        {
            var canonicalRequest = new StringBuilder();

            // 1. HTTP リクエストメソッド (GET、PUT、POST など) を指定し、その後に改行文字を置きます
            canonicalRequest.Append(request.Method + "\n");

            // 2. 正規 URI パラメータを追加し、その後に改行文字を置きます
            canonicalRequest.Append(string.Join("/", request.RequestUri.AbsolutePath.Split('/').Select(Uri.EscapeDataString)) + "\n");

            // 3. 正規クエリ文字列を追加し、その後に改行文字を置きます
            var canonicalQueryParams = GetCanonicalQueryParams(request);
            canonicalRequest.Append(canonicalQueryParams + "\n");

            // 各種リクエストヘッダを付与します
            // hostヘッダ
            request.Headers.Host ??= request.RequestUri.Host;

            // x-amz-dateヘッダ
            var amzDate = utcNow.ToString("yyyyMMddTHHmmssZ");
            request.Headers.TryAddWithoutValidation("x-amz-date", amzDate);

            // 4. 正規ヘッダーを追加し、その後に改行文字を置きます
            var signedHeadersList = new List<string>();
            foreach (var (headerKey, headerValue) in request.Headers.OrderBy(x => x.Key.ToLowerInvariant(), StringComparer.OrdinalIgnoreCase))
            {
                canonicalRequest.Append(headerKey.ToLowerInvariant());
                canonicalRequest.Append(":");
                canonicalRequest.Append(string.Join(",", headerValue.Select(s => s.Trim())));
                canonicalRequest.Append("\n");
                signedHeadersList.Add(headerKey.ToLowerInvariant());
            }
            canonicalRequest.Append("\n");

            // 5. 署名付きヘッダーを追加し、その後に改行文字を置きます
            var signedHeaders = string.Join(";", signedHeadersList);
            canonicalRequest.Append(signedHeaders + "\n");

            // 6. リクエストの本文のペイロードからハッシュ値を作成します
            var content = request.Content != null ? await request.Content.ReadAsByteArrayAsync() : new byte[0];
            canonicalRequest.Append(Hash(content));

            return (canonicalRequest.ToString(), amzDate, signedHeaders);
        }

        /// <summary>
        /// ダイジェスト (ハッシュ) を作成します
        /// </summary>
        /// <param name="bytesToHash"></param>
        /// <returns></returns>
        private string Hash(byte[] bytesToHash)
        {
            var result = sha256.ComputeHash(bytesToHash);
            return ToHexString(result);
        }

        /// <summary>
        /// 署名を計算します
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        private static byte[] HmacSha256(byte[] key, string data)
        {
            var hashAlgorithm = new HMACSHA256(key);

            return hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// 署名キーを取得します
        /// </summary>
        /// <param name="key"></param>
        /// <param name="dateStamp"></param>
        /// <param name="regionName"></param>
        /// <param name="serviceName"></param>
        /// <returns></returns>
        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            var kSecret = Encoding.UTF8.GetBytes("AWS4" + key);
            var kDate = HmacSha256(kSecret, dateStamp);
            var kRegion = HmacSha256(kDate, regionName);
            var kService = HmacSha256(kRegion, serviceName);
            var kSigning = HmacSha256(kService, "aws4_request");
            return kSigning;
        }

        /// <summary>
        /// 16進文字列を生成します
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        private static string ToHexString(byte[] bytes) => BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

        /// <summary>
        /// 正規クエリ文字列を取得します
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        private static string GetCanonicalQueryParams(HttpRequestMessage request)
        {
            var values = new SortedDictionary<string, IEnumerable<string>>();
            var querystring = HttpUtility.ParseQueryString(request.RequestUri.Query);
            foreach (var key in querystring.AllKeys)
            {
                // パラメーター名を文字コードポイントで昇順にソートします。名前が重複しているパラメータは、値でソートする必要があります
                // 16 進数文字（0～9 および大文字の A ～ F）によるパーセントエンコードが必要です
                var queryValues = querystring[key].Split(',')
                    .OrderBy(v => v)
                    .Select(v => $"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(v)}");

                // キー毎にクエリ文字列を格納します
                values.Add(Uri.EscapeDataString(key), queryValues);
            }

            return string.Join("&", values.SelectMany(x => x.Value));
        }
    }
}
