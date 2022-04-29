using Microsoft.AspNetCore.Mvc;
using TestProjectUseRefreshToken.Authorization;
using TestProjectUseRefreshToken.Entities;
using TestProjectUseRefreshToken.Models;
using TestProjectUseRefreshToken.Services.Account;

namespace TestProjectUseRefreshToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly IAccountService _accountService;

        public AccountsController(IAccountService accountService)
        {
            _accountService = accountService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest model)
        {
            try
            {
                await _accountService.RegisterAsync(model, Request.Headers["origin"]);

                return Ok(new { message = "Registration successful, please check your email for verification instructions" });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("authenticate")]
        public async Task<ActionResult<AuthenticateResponse>> Authenticate(AuthenticateRequest model)
        {
            try
            {
                var response = await _accountService.AuthenticateAsync(model, IpAddress());
                SetTokenCookie(response.RefreshToken);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmail(VerifyEmailRequest model)
        {
            try
            {
                await _accountService.VerifyEmailAsync(model.Token);
                return Ok(new { message = "Verification successful, you can now login" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<AuthenticateResponse>> RefreshToken()
        {
            try
            {
                var refreshToken = Request.Cookies["refreshToken"] ?? "";
                var response = await _accountService.RefreshTokenAsync(refreshToken, IpAddress());
                SetTokenCookie(response.RefreshToken);
                return Ok(response);
            }
            catch(KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }


        [Authorize]
        [HttpPost("revoke-token")]
        public async Task<IActionResult> RevokeToken(RevokeTokenRequest model)
        {
            // accept token from request body or cookie
            var token = model.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
                return BadRequest(new { message = "Token is required" });

            var account = HttpContext.Items["Account"] as Account;

            if(account != null && !account.OwnsToken(token))
            {
                return BadRequest(new { message = "Token not found" });
            }

            try
            {
                await _accountService.RevokeTokenAsync(token, IpAddress());
                return Ok(new { message = "Token revoked" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordRequest model)
        {
            try
            {
                await _accountService.ForgotPasswordAsync(model, Request.Headers["origin"]);
                return Ok(new { message = "Please check your email for password reset instructions" });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("validate-reset-token")]
        public async Task<IActionResult> ValidateResetToken(ValidateResetTokenRequest model)
        {
            try
            {
                await _accountService.ValidateResetTokenAsync(model);
                return Ok(new { message = "Token is valid" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequest model)
        {
            try
            {
                await _accountService.ResetPasswordAsync(model);
                return Ok(new { message = "Password reset successful, you can now login" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize(Role.Admin)]
        [HttpGet("all")]
        public async Task<ActionResult<IEnumerable<AccountResponse>>> GetAll()
        {
            return Ok(await _accountService.GetAllAsync());
        }

        [Authorize]
        [HttpGet("one/{id}")]
        public async Task<ActionResult<AccountResponse>> GetById(Guid id)
        {
            var authAccount = HttpContext.Items["Account"] as Account;
            Guid accountId = authAccount!.Role == Role.Admin ? id : authAccount.Id;
            
            try
            {
                var account = await _accountService.GetByIdAsync(accountId);
                return Ok(account);
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize(Role.Admin)]
        [HttpPost("create")]
        public async Task<ActionResult<AccountResponse>> Create(CreateRequest model)
        {
            try
            {
                var account = await _accountService.CreateAsync(model);
                return Ok(account);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [Authorize]
        [HttpDelete("{id}")]
        public async Task<IActionResult> Delete(Guid id)
        {
            var authAccount = HttpContext.Items["Account"] as Account;
            Guid accountId = authAccount!.Role == Role.Admin ? id : authAccount.Id;

            try
            {
                await _accountService.DeleteAsync(accountId);
                return Ok(new { message = "Account deleted successfully" });
            }
            catch (KeyNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // helper methods
        private void SetTokenCookie(string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddDays(7)
            };
            Response.Cookies.Append("refreshToken", token, cookieOptions);
        }

        private string IpAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
            {
                return Request.Headers["X-Forwarded-For"];
            }
            else
            {
                return HttpContext.Connection.RemoteIpAddress!.MapToIPv4().ToString();
            }
        }
    }
}
