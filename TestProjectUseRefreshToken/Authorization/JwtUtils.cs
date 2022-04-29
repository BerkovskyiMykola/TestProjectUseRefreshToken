namespace TestProjectUseRefreshToken.Authorization;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestProjectUseRefreshToken.Entities;
using TestProjectUseRefreshToken.Helpers;

public class JwtUtils : IJwtUtils
{
    private readonly DataContext _context;
    private readonly AppSettings _appSettings;

    public JwtUtils(
        DataContext context,
        IOptions<AppSettings> appSettings)
    {
        _context = context;
        _appSettings = appSettings.Value;
    }

    public string GenerateJwtToken(Account account)
    {
        // generate token that is valid for 15 minutes
        var tokenHandler = new JwtSecurityTokenHandler();

        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim("id", account.Id.ToString()) }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public async Task<RefreshToken> GenerateRefreshTokenAsync(string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            // token is a cryptographically strong random sequence of values
            Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64)),
            // token is valid for 7 days
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };

        // ensure token is unique by checking against db
        var tokenIsUnique = !await _context.Accounts.AnyAsync(a => a.RefreshTokens.Any(t => t.Token == refreshToken.Token));

        if (!tokenIsUnique)
            return await GenerateRefreshTokenAsync(ipAddress);

        return refreshToken;
    }

    public async Task<Guid?> ValidateJwtTokenAsync(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        try
        {
            var result = await tokenHandler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = false,
                ValidateAudience = false,
                // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                ClockSkew = TimeSpan.Zero
            });

            // return account id from JWT token if validation successful
            return result.Claims.First(x => x.Key == "id").Value is not string id ? null : Guid.Parse(id);
        }
        catch
        {
            // return null if validation fails
            return null;
        }
    }
}

