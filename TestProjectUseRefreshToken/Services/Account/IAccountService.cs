namespace TestProjectUseRefreshToken.Services.Account;

using TestProjectUseRefreshToken.Models;

public interface IAccountService
{
    Task<AuthenticateResponse> AuthenticateAsync(AuthenticateRequest model, string ipAddress);
    Task<AuthenticateResponse> RefreshTokenAsync(string token, string ipAddress);
    Task RevokeTokenAsync(string token, string ipAddress);
    Task RegisterAsync(RegisterRequest model, string origin);
    Task VerifyEmailAsync(string token);
    Task ForgotPasswordAsync(ForgotPasswordRequest model, string origin);
    Task ValidateResetTokenAsync(ValidateResetTokenRequest model);
    Task ResetPasswordAsync(ResetPasswordRequest model);
    Task<IEnumerable<AccountResponse>> GetAllAsync();
    Task<AccountResponse> GetByIdAsync(Guid id);
    Task<AccountResponse> CreateAsync(CreateRequest model);
    Task<AccountResponse> UpdateAsync(Guid id, UpdateRequest model);
    Task DeleteAsync(Guid id);
}