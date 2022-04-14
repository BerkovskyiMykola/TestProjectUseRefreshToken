namespace TestProjectUseRefreshToken.Models;

using System.ComponentModel.DataAnnotations;

public class ValidateResetTokenRequest
{
    [Required]
    public string Token { get; set; } = string.Empty;
}