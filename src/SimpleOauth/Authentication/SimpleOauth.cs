using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SimpleOAuth.Interfaces;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using SimpleOAuth.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;

namespace SimpleOAuth.Authentication
{
    public static class SimpleOAuth
    {
        public static async Task<HttpContext> LoginOAuth(this HttpContext context, IApplicationBuilder app)
        {
            IAuthorizationRoles authorizationRoles;
            OAuthSimpleOption options;

            using (var scope = app.ApplicationServices.GetService<IServiceScopeFactory>().CreateScope())
            {
                authorizationRoles = scope.ServiceProvider.GetRequiredService<IAuthorizationRoles>();
                options = scope.ServiceProvider.GetRequiredService<OAuthSimpleOption>();
            }

            string body = "";
            using (var reader = new StreamReader(context.Request.Body))
            {
                body = await reader.ReadToEndAsync();
            }

            var authorize = JsonConvert.DeserializeObject<JObject>(body);

            var jwtValue = await CreateTokenAsync(authorize, authorizationRoles, options);

            context.Response.StatusCode = jwtValue.StatusCode;

            if (context.Response.StatusCode == 200)
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(jwtValue.JsonReturn);
            }

            return context;
        }

        private static void CreateResponsePassword(
            AuthorizationRolesPassword authorizationRoles, 
            OAuthSimpleOption options,
            JwtValue value
            )
        {
            if (authorizationRoles.Authorized)
            {
                value.JsonReturn = CreateTokenRefresh(GenerateToken(options, authorizationRoles), options, authorizationRoles.RefreshToken);
            }
            else
            {
                value.StatusCode = 401;
            }
        }

        private static void CreateResponseClient(
            AuthorizationRolesClient authorizationRoles, 
            OAuthSimpleOption options,
             JwtValue value)
        {
            if (authorizationRoles.Authorized)
            {
              
                var handler = new JwtSecurityTokenHandler();
                var tokenValue = new AuthorizationClientPass
                {
                    Access_token = GenerateToken(options, authorizationRoles),
                    Expires_in = DateTime.UtcNow.AddMinutes(options.ExpireTimeMinutes).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'"),
                    Token_type = "Bearer"
                };

                value.JsonReturn = JsonConvert.SerializeObject(tokenValue);
            }
            else
            {
                value.StatusCode = 401;
            }
        }

        private static string CreateTokenRefresh(string token, OAuthSimpleOption options, string refreshToken)
        {
            var handler = new JwtSecurityTokenHandler();
            var tokenValue = new AuthorizationRefreshPass
            {
                Access_token = token,
                Expires_in = DateTime.UtcNow.AddMinutes(options.ExpireTimeMinutes).ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'"),
                Token_type = "Bearer",
                Refresh_token = refreshToken
            };

            return JsonConvert.SerializeObject(tokenValue);
        }

        private static string GetGrantType(JObject authorize)
        {
            string grantType = null;
            if (authorize.ContainsKey("Grant_type"))
            {
                grantType = authorize.Value<string>("Grant_type");
            }
            else if (authorize.ContainsKey("grant_type"))
            {
                grantType = authorize.Value<string>("grant_type");
            }
            else if (authorize.ContainsKey("Grant_Type"))
            {
                grantType = authorize.Value<string>("Grant_Type");
            }
            else if (authorize.ContainsKey("GrantType"))
            {
                grantType = authorize.Value<string>("GrantType");
            }
            else if (authorize.ContainsKey("granttype"))
            {
                grantType = authorize.Value<string>("granttype");
            }


            return grantType;
        }

        public static string GenerateToken(OAuthSimpleOption options, AuthorizationRolesBasic authorization)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(authorization.Claims),
                Expires = DateTime.UtcNow.AddMinutes(options.ExpireTimeMinutes),
                SigningCredentials = options.SigningConfigurations.SigningCredentials,
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static async Task<JwtValue> CreateTokenAsync(JObject authorize, IAuthorizationRoles authorizationRoles, OAuthSimpleOption options)
        
        {
            var @return = new JwtValue() { StatusCode = StatusCodes.Status200OK };

            string grantType = GetGrantType(authorize);

            if (string.IsNullOrEmpty(grantType))
            {
                @return.StatusCode = StatusCodes.Status401Unauthorized;
            }
            else
            {
                try
                {
                    switch (grantType.ToLower())
                    {
                        case Const.Types.Password:
                            var password = authorize.ToObject<Models.OAuthPassword>();
                            var passwordRoles = await authorizationRoles.PasswordAuthorizationAsync(password);
                            CreateResponsePassword(passwordRoles, options, @return);
                            break;
                        case Const.Types.Client:
                            var client = authorize.ToObject<Models.OAuthClient>();
                            var clientRoles = await authorizationRoles.ClientCredentialsAuthorizationAsync(client);
                            CreateResponseClient(clientRoles, options, @return);
                            break;
                        case Const.Types.RefreshToken:
                            var refresh = authorize.ToObject<Models.OAuthRefreshToken>();
                            var refreshRoles = await authorizationRoles.RefreshTokenCredentialsAuthorizationAsync(refresh);
                            CreateResponsePassword(refreshRoles, options, @return);
                            break;
                        default:
                            @return.StatusCode = StatusCodes.Status401Unauthorized;
                            break;
                    }
                }
                catch (Exception e)
                {
                    @return.StatusCode = StatusCodes.Status401Unauthorized;
                }
            }

            return @return;
        }
    }
}
