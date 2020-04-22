using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Text;

namespace SimpleOAuth.Models
{
    public class SigningConfigurations
    {
        public SecurityKey Key { get; private set; }
        public SigningCredentials SigningCredentials { get; private set; }

        public SigningConfigurations(string key)
        {
            Key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key));
            SigningCredentials = new SigningCredentials(
                Key, SecurityAlgorithms.HmacSha256);
        }
    }
}
