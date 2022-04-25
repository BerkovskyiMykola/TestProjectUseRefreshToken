namespace TestProjectUseRefreshToken.Authorization;

using TestProjectUseRefreshToken.Entities;

public interface IJwtUtils
{
    string GenerateJwtToken(Account account);
    Task<Guid?> ValidateJwtTokenAsync(string token);
    Task<RefreshToken> GenerateRefreshTokenAsync(string ipAddress);
}
