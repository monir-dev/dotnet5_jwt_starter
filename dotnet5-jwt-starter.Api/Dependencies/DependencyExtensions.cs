using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotnet5_jwt_starter.Api.Dependencies
{
    public static class DependencyExtensions
    {
        public static void InitializeServicesInAssembly(this IServiceCollection services, IConfiguration configuration)
        {
            var dependencies = typeof(Startup).Assembly.ExportedTypes.Where(x =>
            typeof(IDependency).IsAssignableFrom(x) && !x.IsInterface && !x.IsAbstract).Select(Activator.CreateInstance).Cast<IDependency>().ToList();

            dependencies.ForEach(dependency => dependency.InitializeSevices(services, configuration));
        }
    }
}
