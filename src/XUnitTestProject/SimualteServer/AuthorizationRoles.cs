using SimpleOAuth.Interfaces;
using SimpleOAuth.Models;
using System;
using System.Security.Claims;
using System.Threading.Tasks;

namespace XUnitTestProject.SimualteServer
{
    public class AuthorizationRoles : IAuthorizationRoles
    {
        public async Task<AuthorizationRolesClient> ClientCredentialsAuthorizationAsync(OAuthClient client)
        {
            return await Task.FromResult(new AuthorizationRolesClient
            {
                Authorized =true,
                Claims = new Claim[] {
                new Claim("Test","5")
                },
            });
        }

        public async Task<AuthorizationRolesPassword> PasswordAuthorizationAsync(OAuthPassword oauthPassword)
        {
            return await Task.FromResult(new AuthorizationRolesPassword
            {
                Authorized = true,
                Claims = new Claim[] {
                new Claim("Test","5")
                },
                RefreshToken = Guid.NewGuid().ToString("N")
            });

        }

        public async Task<AuthorizationRolesRefresh> RefreshTokenCredentialsAuthorizationAsync(OAuthRefreshToken refreshToken)
        {
            return await Task.FromResult(new AuthorizationRolesRefresh
            {
                Authorized = true,
                Claims = new Claim[] {
                new Claim("Test","5")
                },
                RefreshToken = Guid.NewGuid().ToString("N")
            });
        }
    }
}
