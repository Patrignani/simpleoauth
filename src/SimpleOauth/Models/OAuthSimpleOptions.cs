namespace SimpleOAuth.Models
{
    public class OAuthSimpleOption
    {
        public OAuthSimpleOption()
        {
            Audience = "";
            Issuer = "";
            AuthRouter = "/";
        }

        public void AddKeyToken(string key)
        {
            Key = key;
            SigningConfigurations = new SigningConfigurations(key);
        }

        public void AddExpireTimeMinutes(int time)
        {
            ExpireTimeMinutes = time;
        }

        public void AddAudience(string audience) => Audience = audience;
        public void AddIssuer(string issuer) => Issuer = issuer;
        public void AddAtuhRouter(string authRouter) => AuthRouter = authRouter;

        public string Key { get; private set; }
        //aud (audience) = Destinatário do token, representa a aplicação que 
        public string Audience { get; private set; }
        public int ExpireTimeMinutes { get; private set; }
        //iss(issuer) = Emissor do token;
        public string Issuer { get; private set; }
        public string AuthRouter { get; private set; }
        public SigningConfigurations SigningConfigurations { get; private set; }
    }
}