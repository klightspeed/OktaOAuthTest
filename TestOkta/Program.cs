using Microsoft.Extensions.Configuration;
using Okta.Sdk.Api;
using Okta.Sdk.Client;
using Okta.Sdk.Model;
using RestSharp;
using System.Reflection;
using TestOkta;

var configroot =
    new ConfigurationBuilder()
        .AddJsonFile("appsettings.json", optional: true)
        .AddUserSecrets(Assembly.GetExecutingAssembly(), optional: true)
        .Build();

var oktaConfig = configroot.GetSection("Okta").Get<Configuration>() ?? new();

Configuration.Validate(oktaConfig);
var oauthTokenProvider = new DefaultOAuthTokenProvider(oktaConfig);
var apiconfig = new OktaApiClientOptions(oktaConfig, oauthTokenProvider, httpMessageHandler: new CustomHttpClientHandler(oktaConfig));

var apiClient = new ApiClient(apiconfig);
var groupApi = new GroupApi(apiconfig);

Console.WriteLine($"Dotnet version: {System.Environment.Version}");
Console.WriteLine($"Okta SDK Version: {typeof(Configuration).Assembly.GetName().Version}");

Console.WriteLine();
Console.WriteLine("Requesting first group");
var group = await groupApi.ListGroups(limit: 1).FirstAsync();
var reqopts = new RequestOptions();

if (ClientUtils.SelectHeaderContentType([]) is string contentType)
{
    reqopts.HeaderParameters.Add("Content-Type", contentType);
}

if (ClientUtils.SelectHeaderAccept(["application/json"]) is string accept)
{
    reqopts.HeaderParameters.Add("Accept", accept);
}

Console.WriteLine();
Console.WriteLine("Requesting members via client");

// This request works
var members1 = await new OktaCollectionClient<User>(reqopts, $"/api/v1/groups/{group.Id}/users", apiClient, oktaConfig, oauthTokenProvider).ToListAsync();

Console.WriteLine();
Console.WriteLine("Requesting membes via GroupApi");

// This request does not
var members = await groupApi.ListGroupUsers(group.Id).ToListAsync();
