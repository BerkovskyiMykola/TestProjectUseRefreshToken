namespace TestProjectUseRefreshToken.Authorization;

using TestProjectUseRefreshToken.Entities;

public interface IJwtUtils
{
    string GenerateJwtToken(Account account);
    Guid? ValidateJwtToken(string? token);
    Task<RefreshToken> GenerateRefreshTokenAsync(string ipAddress);
}
