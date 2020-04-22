using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using SimpleOAuth.Models;

namespace SimpleOAuth.Interfaces
{
    public interface IAuthorizationRoles
    {
        Task<AuthorizationRolesPassword> PasswordAuthorizationAsync(OAuthPassword oauthPassword);
        Task<AuthorizationRolesClient> ClientCredentialsAuthorizationAsync(OAuthClient client);
        Task<AuthorizationRolesRefresh> RefreshTokenCredentialsAuthorizationAsync(OAuthRefreshToken refreshToken);

    }
}
