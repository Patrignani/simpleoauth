
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SimpleOAuth.Authentication;
using SimpleOAuth.Models;
using System;

namespace SimpleOAuth
{
    public static class Middleware
    {
        public static IServiceCollection AddSimpleOAuth(this IServiceCollection services, Action<OAuthSimpleOption> options)
        {
            var config = new OAuthSimpleOption();
            options(config);

            services.AddHttpContextAccessor();

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
            services.AddScoped(provider =>
            {
                return new TokenRead(provider.GetService<IHttpContextAccessor>()
                    .HttpContext?.Request?.Headers["Authorization"], provider.GetService<IHttpContextAccessor>()
                    .HttpContext?.Request?.HttpContext?.Connection?.RemoteIpAddress);

            });

            return services;
        }

        public static IApplicationBuilder UseSimpleOAuth(this IApplicationBuilder app)
        {
            app.UseAuthentication();
            app.UseAuthorization();

            return app;
        }

        public static IEndpointRouteBuilder AddAuth(this IEndpointRouteBuilder endpoints, IApplicationBuilder app)
        {
            var router = "";
            using (var scope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                var options = scope.ServiceProvider.GetRequiredService<OAuthSimpleOption>();
                router = options.AuthRouter;
            }

            endpoints.MapPost(router, context => context.LoginOAuth(app));

            return endpoints;
        }
    }
}