namespace TestProjectUseRefreshToken.Models;

using System.ComponentModel.DataAnnotations;

public class VerifyEmailRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;
}