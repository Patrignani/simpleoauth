using SimpleOAuth.Interfaces;
using SimpleOAuth.Models;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace test
{
    public class AuthorizationRoles : IAuthorizationRoles
    {
        public Task<SimpleOAuth.Models.AuthorizationRolesClient> ClientCredentialsAuthorizationAsync(OAuthClient client)
        {
            return Task.FromResult(new SimpleOAuth.Models.AuthorizationRolesClient {
                ExpireTimeMinutes = 1,
                Claims = new List<Claim> {
                new Claim("client",@"{""Id"":""4035a569-1983-48d8-a537-ce661b6a0d10"",""Identification"":""Front-End"",""User"":{""Id"":""36e05ad4-8e5d-43f0-bfae-63756342bb66"",""Identification"":""First"",""Email"":""anderson.patrignani@gmail.com""}}")
                },
                Authorized = true
            }); ;
        }

        public Task<SimpleOAuth.Models.AuthorizationRolesPassword> PasswordAuthorizationAsync(OAuthPassword oauthPassword)
        {
            return Task.FromResult(new SimpleOAuth.Models.AuthorizationRolesPassword
            {
                Errors = new List<string>()
                {
                "TESTTTTTTTTTTTTT",
                "aaaa"
                },
                ExpireTimeMinutes = 10,
                Claims = new List<Claim> {
                new Claim("client",@"{""Id"":""4035a569-1983-48d8-a537-ce661b6a0d10"",""Identification"":""Front-End"",""User"":{""Id"":""36e05ad4-8e5d-43f0-bfae-63756342bb66"",""Identification"":""First"",""Email"":""anderson.patrignani@gmail.com""}}")
                },
                Authorized = true,
                RefreshToken = Guid.NewGuid().ToString("N")
            }); ;
        }

        public Task<AuthorizationRolesRefresh> RefreshTokenCredentialsAuthorizationAsync(OAuthRefreshToken refreshToken)
        {
            return Task.FromResult(new SimpleOAuth.Models.AuthorizationRolesRefresh
            {
                ExpireTimeMinutes = 5,
                Claims = new List<Claim> {
                new Claim("client",@"{""Id"":""4035a569-1983-48d8-a537-ce661b6a0d10"",""Identification"":""Front-End"",""User"":{""Id"":""36e05ad4-8e5d-43f0-bfae-63756342bb66"",""Identification"":""First"",""Email"":""anderson.patrignani@gmail.com""}}")
                },
                Authorized = true,
                RefreshToken = Guid.NewGuid().ToString("N")
            }); 
        }
    }
}
