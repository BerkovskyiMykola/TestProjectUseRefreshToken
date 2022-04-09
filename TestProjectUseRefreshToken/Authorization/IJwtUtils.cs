namespace TestProjectUseRefreshToken.Authorization;

using TestProjectUseRefreshToken.Entities;

public interface IJwtUtils
{
    string GenerateJwtToken(Account account);
    Guid? ValidateJwtToken(string token);
    RefreshToken GenerateRefreshToken(string ipAddress);
}
