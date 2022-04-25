using System.Reflection.Emit;
using System.Text;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.ConstrainedExecution;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using bs_JWT.Models;
using System.Threading.Tasks;
using System.Linq;

namespace bs_JWT.Helper
{
    public class JwtHelper
    {
        private readonly IConfiguration Configuration;
        private readonly JWTContext _context;

        public JwtHelper(IConfiguration configuration, JWTContext context)
        {
            Configuration = configuration;
            _context = context;
        }

        public async Task<AuthResult> GenerateToken(string userName, int expireMinute = 30)
        {
            var issuer = Configuration.GetValue<string>("JwtSettings:Issuer");
            var signKey = Configuration.GetValue<string>("JwtSettings:SignKey");

            var claims = new List<Claim>();

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, userName));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            claims.Add(new Claim("roles", "Admin"));
            claims.Add(new Claim("role", "Users"));

            var userClaimsIdentity = new ClaimsIdentity(claims);

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signKey));

            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Issuer = issuer,
                Subject = userClaimsIdentity,
                Expires = DateTime.UtcNow.AddSeconds(20),
                SigningCredentials = signingCredentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(tokenDescriptor);
            var serializeToken = tokenHandler.WriteToken(securityToken);

            var refreshToken = new RefreshToken()
            {
                Username = userName,
                Token = Guid.NewGuid().ToString()
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResult()
            {
                Token = serializeToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        public RefreshToken GetRefreshToken(string refreshToken)
        {
            var source = _context.RefreshTokens.FirstOrDefault(x => x.Token == refreshToken);

            if (source is null) return default;

            return source;
        }
    }
}