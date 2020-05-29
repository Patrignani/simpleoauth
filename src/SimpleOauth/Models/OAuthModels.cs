using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

namespace SimpleOAuth.Models
{
    public abstract class OAuthBasic
    {
        public string Grant_type { get; set; }
        public string Client_id { get; set; }
        public string Client_secret { get; set; }
    }

    public abstract class AuthorizationBasic
    {
        public string Token_type { get; set; }
        public string Expires_in { get; set; }
        public string Access_token { get; set; }
    }

    public class OauthObject
    {

    }

    public class AuthorizationClientPass : AuthorizationBasic
    {
    }

    public class AuthorizationRefreshPass : AuthorizationBasic
    {
        public string Refresh_token { get; set; }
    }


    public class OAuthPassword : OAuthBasic
    {
        public string Username { get; set; }
        public string Password { get; set; }

    }

    public class OAuthClient : OAuthBasic
    {

    }

    public class OAuthRefreshToken : OAuthBasic
    {
        public string Refresh_token { get; set; }
    }

    public class AuthorizationRolesBasic
    {
        public AuthorizationRolesBasic()
        {
            Errors = new List<string>();
        }

        public bool Authorized { get; set; }
        public ICollection<Claim> Claims { get; set; }
        public int ExpireTimeMinutes { get; set; }
        public ICollection<string> Errors { get; set; }

    }

    public class AuthorizationRolesPassword : AuthorizationRolesBasic
    {
        public string RefreshToken { get; set; }
    }

    public class AuthorizationRolesClient : AuthorizationRolesBasic
    {
    }

    public class AuthorizationRolesRefresh : AuthorizationRolesPassword
    {

    }

    public class JwtValue
    {
        public string JsonReturn { get; set; }
        public int StatusCode { get; set; }
        public string Error { get; set; }
    }

    public class TokenRead
    {
        public TokenRead(string fullToken, object ip)
        {
            FullToken = fullToken;
            IpAndress = ip;
            if (!string.IsNullOrEmpty(FullToken))
            {
                var token = FullToken.Split(" ");
                Token = token.Length > 1 ? token[token.Length - 1] : FullToken;
            }
            else
            {
                Token = string.Empty;
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var token = handler.ReadJwtToken(String.IsNullOrEmpty(Token) ? FullToken : Token);
                JwtSecurityToken = token;
                Claims = token.Claims.ToList();
            
            }
            catch
            { 
            
            }

        }
        public IList<Claim> Claims { get; }
        public string FullToken { get; private set; }
        public string Token { get; private set; }
        public object IpAndress { get; private set; }
        public JwtSecurityToken JwtSecurityToken { get; private set; }

        public string GetValue(string type) => Claims.Where(x => x.Type == type).Select(x => x.Value).FirstOrDefault();

        public TValue GetJsonObject<TValue>(string type) => Claims.Where(x => x.Type == type)
            .Select(x => Newtonsoft.Json.JsonConvert.DeserializeObject<TValue>(x.Value)).FirstOrDefault();
    }
}
