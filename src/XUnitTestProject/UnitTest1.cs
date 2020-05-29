using Microsoft.IdentityModel.Tokens;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SimpleOAuth.Interfaces;
using SimpleOAuth.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using XUnitTestProject.SimualteServer;

namespace XUnitTestProject
{
    public class UnitTest1
    {
        private readonly OAuthSimpleOption _options;
        private readonly AuthorizationRoles _authorizationRoles;

        public UnitTest1()
        {
            _options = new OAuthSimpleOption();
            _options.AddKeyToken("kl3fj8990asfd123klbvc7m243hjioa90142mkrtdsfd789a");
            _authorizationRoles = new AuthorizationRoles();
        }

        [Fact]
        public async Task TestPassword()
        {
            OAuthPassword aouthPassword = new OAuthPassword
            {
                Client_id = "FrontEnd",
                Client_secret = "Fr0nt3nd123",
                Grant_type = "Password",
                Password = "123456",
                Username = "T3st3"
            };

            var jwtValue = await SimpleOAuth.Authentication.SimpleOAuth.CreateTokenAsync(CreateJsonObject(aouthPassword),
                _authorizationRoles, _options);

            AuthorizationRefreshPass pass = JsonConvert.DeserializeObject<AuthorizationRefreshPass>(jwtValue.JsonReturn);

            var tokenValidd = ValidateToken(pass.Access_token);

            Assert.True(tokenValidd && jwtValue.StatusCode == 200);

        }

        [Fact]
        public async Task TestClient()
        {
            var aouthClient = new OAuthClient
            {
                Client_id = "1nt3gr4t10n",
                Client_secret = "1nt3gr4t10n23",
                Grant_type = "client_credentials"
            };

            var jwtValue = await SimpleOAuth.Authentication.SimpleOAuth.CreateTokenAsync(CreateJsonObject(aouthClient),
                _authorizationRoles, _options);

            AuthorizationRefreshPass pass = JsonConvert.DeserializeObject<AuthorizationRefreshPass>(jwtValue.JsonReturn);

            var tokenValidd = ValidateToken(pass.Access_token);

            Assert.True(tokenValidd && jwtValue.StatusCode == 200);

        }


        [Fact]
        public async Task TestRefresh()
        {
            var oauthRefreshToken = new OAuthRefreshToken
            {
                Client_id = "1nt3gr4t10n",
                Client_secret = "1nt3gr4t10n23",
                Grant_type = "client_credentials",
                Refresh_token = Guid.NewGuid().ToString("N")
            };

            var jwtValue = await SimpleOAuth.Authentication.SimpleOAuth.CreateTokenAsync(CreateJsonObject(oauthRefreshToken),
                _authorizationRoles, _options);

            AuthorizationRefreshPass pass = JsonConvert.DeserializeObject<AuthorizationRefreshPass>(jwtValue.JsonReturn);

            var tokenValidd = ValidateToken(pass.Access_token);

            Assert.True(tokenValidd && jwtValue.StatusCode == 200);

        }

        private  bool ValidateToken(string authToken)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var validationParameters = GetValidationParameters();

                SecurityToken validatedToken;
                IPrincipal principal = tokenHandler.ValidateToken(authToken, validationParameters, out validatedToken);
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        private  TokenValidationParameters GetValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateLifetime = true, 
                ValidateAudience = false, 
                ValidateIssuer = false,   
                IssuerSigningKey = _options.SigningConfigurations.Key // The same key as the one that generate the token
            };
        }


        private JObject CreateJsonObject(object value)
        {
            var json =JsonConvert.SerializeObject(value);
            return JsonConvert.DeserializeObject<JObject>(json);

        }
    }
}
