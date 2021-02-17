using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Configuration;

namespace dotnet5_jwt_starter
{
    public static class Tools
    {
        public static string GetConnectionString(string name = "DefaultConnection")
        {
            return ConfigurationManager.ConnectionStrings[name].ConnectionString;
        }
    }
}
