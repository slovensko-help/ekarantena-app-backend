﻿using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sygic.Corona.Application;
using Sygic.Corona.Infrastructure;
using Sygic.Corona.TracingApi;

[assembly: FunctionsStartup(typeof(Startup))]
namespace Sygic.Corona.TracingApi
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            var config = new ConfigurationBuilder()
                .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            builder.Services.AddApplication()
                .AddInfrastructure(config);
        }
    }
}
