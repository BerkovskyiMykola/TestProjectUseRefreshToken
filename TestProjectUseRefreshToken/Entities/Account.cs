namespace TestProjectUseRefreshToken.Entities;

public class Account
{
    public Guid Id { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool AcceptTerms { get; set; }
    public Role Role { get; set; }
    public string VerificationToken { get; set; } = string.Empty;
    public DateTime? Verified { get; set; }
    public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
    public string ResetToken { get; set; } = string.Empty;
    public DateTime? ResetTokenExpires { get; set; }
    public DateTime? PasswordReset { get; set; }
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public List<RefreshToken> RefreshTokens { get; set; } = new();

    public bool OwnsToken(string token) 
    {
        return RefreshTokens?.Find(x => x.Token == token) != null;
    }
}