using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace dotnet5_jwt_starter.Api.Dependencies
{
    public interface IDependency
    {
        void InitializeSevices(IServiceCollection services,IConfiguration configuration);
    }
}
