# dotnet-core-aws-signature
.NET Core で AWS 署名バージョン4 でリクエストを署名するサンプル

## Feature
- .NET Core 3.1
- AWS Signature Version 4

## Project
- DotNetCoreAwsSignature.Library
    - ライブラリ本体
- DotNetCoreAwsSignature.ConsoleApp
    - サンプル実装を行ったコンソールアプリケーション

## Note
- 署名バージョン4 を利用して IAMで保護された API Gateway に対してリクエストを送信するサンプルです。
- DotNetCoreAwsSignature.ConsoleApp > Program.cs の下記設定値を書き換えてご利用ください。

```c#
// IAM ユーザの情報
var accessKey = "xxx";
var secretKey = "xxx";
```

```c#
// API Gateway のエンドポイント
var url = new Uri("https://xxx");
```
