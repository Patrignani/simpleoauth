
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SimpleOAuth.Models;
using System;
using System.Text;

namespace SimpleOAuth
{
    public static class Middleware
    {
        public static IServiceCollection AddSimpleOAuth(this IServiceCollection services, Action<OAuthSimpleOption> options)
        {
            var config = new OAuthSimpleOption();
            options(config);
          

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = config.SigningConfigurations.Key,
                    ValidateIssuer = false,
                    ValidateAudience = false
                };
            });

            services.Configure(options);
            services.AddSingleton(resolver => resolver.GetRequiredService<IOptions<OAuthSimpleOption>>().Value);

            return services;
        }

        public static IApplicationBuilder UseSimpleOAuth(this IApplicationBuilder app)
        {
            app.UseAuthentication();
   
            return app;
        }
    }
}