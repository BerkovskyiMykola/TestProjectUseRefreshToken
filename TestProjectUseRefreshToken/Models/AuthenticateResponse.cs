namespace TestProjectUseRefreshToken.Models;

using System.Text.Json.Serialization;

public class AuthenticateResponse
{
    public Guid Id { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public bool IsVerified { get; set; }
    public string JwtToken { get; set; } = string.Empty;

    [JsonIgnore] // refresh token is returned in http only cookie
    public string RefreshToken { get; set; } = string.Empty;
}