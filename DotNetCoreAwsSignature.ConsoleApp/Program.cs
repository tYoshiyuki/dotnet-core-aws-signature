using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using DotNetCoreAwsSignature.Library;

namespace DotNetCoreAwsSignature.ConsoleApp
{
    class Program
    {
        static async System.Threading.Tasks.Task Main(string[] args)
        {
            // IAM ユーザの情報
            var accessKey = "xxx";
            var secretKey = "xxx";
            var signer = new AwsRequestSigner(accessKey, secretKey);

            // API Gateway のエンドポイント
            var url = new Uri("https://xxx");

            // リクエスト情報を設定します
            // 送信先エンドポイントに合わせて適宜設定してください
            var content = new StringContent(JsonSerializer.Serialize(new Dictionary<string, string> { { "sampleKey", "sampleValue" } }), Encoding.UTF8, "application/json");
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = url,
                Content = content
            };

            // 署名を行います
            var service = "execute-api"; // API Gatewayのサービス名
            var region = "ap-northeast-1";
            await signer.Sign(request, service, region);

            // 署名を用いてリクエストを送信します
            var client = new HttpClient();
            var response = await client.SendAsync(request);

            // 送信結果を確認します
            Console.WriteLine($"StatusCode: {response.StatusCode}");
            Console.WriteLine($"Response: {response.Content.ReadAsStringAsync().Result}");
        }
    }
}
