namespace TestProjectUseRefreshToken.Services.Account;

using AutoMapper;
using Microsoft.Extensions.Options;
using TestProjectUseRefreshToken.Authorization;
using TestProjectUseRefreshToken.Helpers;
using TestProjectUseRefreshToken.Models;
using TestProjectUseRefreshToken.Services.Email;
using BCrypt.Net;
using TestProjectUseRefreshToken.Entities;
using Microsoft.EntityFrameworkCore;
using TestProjectUseRefreshToken.Exceptions;
using System.Security.Cryptography;

public class AccountService : IAccountService
{
    private readonly DataContext _context;
    private readonly IJwtUtils _jwtUtils;
    private readonly IMapper _mapper;
    private readonly AppSettings _appSettings;
    private readonly IEmailService _emailService;

    public AccountService(
        DataContext context,
        IJwtUtils jwtUtils,
        IMapper mapper,
        IOptions<AppSettings> appSettings,
        IEmailService emailService)
    {
        _context = context;
        _jwtUtils = jwtUtils;
        _mapper = mapper;
        _appSettings = appSettings.Value;
        _emailService = emailService;
    }

    public async Task<AuthenticateResponse> AuthenticateAsync(AuthenticateRequest model, string ipAddress)
    {
        var account = await _context.Accounts
            .Include(x => x.RefreshTokens)
            .SingleOrDefaultAsync(x => x.Email == model.Email);

        // validate
        if (account == null || !account.IsVerified || !BCrypt.Verify(model.Password, account.PasswordHash))
        {
            throw new KeyNotFoundException("Email or password is incorrect");
        }

        // authentication successful so generate jwt and refresh tokens
        var jwtToken = _jwtUtils.GenerateJwtToken(account);
        var refreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        account.RefreshTokens.Add(refreshToken);

        // remove old refresh tokens from account
        RemoveOldRefreshTokens(account);

        // save changes to db
        _context.Update(account);
        await _context.SaveChangesAsync();

        var response = _mapper.Map<AuthenticateResponse>(account);
        response.JwtToken = jwtToken;
        response.RefreshToken = refreshToken.Token;
        return response;
    }

    public async Task<AuthenticateResponse> RefreshTokenAsync(string token, string ipAddress)
    {
        var account = await GetAccountByRefreshTokenAsync(token);
        var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

        if (refreshToken.IsRevoked)
        {
            // revoke all descendant tokens in case this token has been compromised
            RevokeDescendantRefreshTokens(refreshToken, account, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
            _context.Update(account);
            await _context.SaveChangesAsync();
        }

        if (!refreshToken.IsActive)
        {
            throw new TokenIsNotActiveException("Invalid token");
        }

        // replace old refresh token with a new one (rotate token)
        var newRefreshToken = RotateRefreshToken(refreshToken, ipAddress);
        account.RefreshTokens.Add(newRefreshToken);

        // remove old refresh tokens from account
        RemoveOldRefreshTokens(account);

        // save changes to db
        _context.Update(account);
        await _context.SaveChangesAsync();

        // generate new jwt
        var jwtToken = _jwtUtils.GenerateJwtToken(account);

        // return data in authenticate response object
        var response = _mapper.Map<AuthenticateResponse>(account);
        response.JwtToken = jwtToken;
        response.RefreshToken = newRefreshToken.Token;
        return response;
    }

    public async Task RevokeTokenAsync(string token, string ipAddress)
    {
        var account = await GetAccountByRefreshTokenAsync(token);
        var refreshToken = account.RefreshTokens.Single(x => x.Token == token);

        if (!refreshToken.IsActive)
        {
            throw new TokenIsNotActiveException("Invalid token");
        }

        // revoke token and save
        RevokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        _context.Update(account);
        await _context.SaveChangesAsync();
    }

    public async Task RegisterAsync(RegisterRequest model, string origin)
    {
        // validate
        if (await _context.Accounts.AnyAsync(x => x.Email == model.Email))
        {
            // send already registered error in email to prevent account enumeration
            await SendAlreadyRegisteredEmailAsync(model.Email, origin);
            return;
        }

        // map model to new account object
        var account = _mapper.Map<Account>(model);

        // first registered account is an admin
        var isFirstAccount = await _context.Accounts.CountAsync() == 0;
        account.Role = isFirstAccount ? Role.Admin : Role.User;
        account.Created = DateTime.UtcNow;
        account.VerificationToken = await GenerateVerificationTokenAsync();

        // hash password
        account.PasswordHash = BCrypt.HashPassword(model.Password);

        // save account
        _context.Accounts.Add(account);
        _context.SaveChanges();

        // send email
        await SendVerificationEmailAsync(account, origin);
    }

    public async Task VerifyEmailAsync(string token)
    {
        var account = await _context.Accounts.SingleOrDefaultAsync(x => x.VerificationToken == token);

        if (account == null)
        {
            throw new KeyNotFoundException("Verification failed");
        }

        account.Verified = DateTime.UtcNow;
        account.VerificationToken = "";

        _context.Accounts.Update(account);
        await _context.SaveChangesAsync();
    }

    public async Task ForgotPasswordAsync(ForgotPasswordRequest model, string origin)
    {
        var account = await _context.Accounts.SingleOrDefaultAsync(x => x.Email == model.Email);

        // always return ok response to prevent email enumeration
        if (account == null) return;

        // create reset token that expires after 1 day
        account.ResetToken = await GenerateResetTokenAsync();
        account.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

        _context.Accounts.Update(account);
        await _context.SaveChangesAsync();

        // send email
        await SendPasswordResetEmailAsync(account, origin);
    }

    public async Task ValidateResetTokenAsync(ValidateResetTokenRequest model)
    {
        await GetAccountByResetTokenAsync(model.Token);
    }

    public async Task ResetPasswordAsync(ResetPasswordRequest model)
    {
        var account = await GetAccountByResetTokenAsync(model.Token);

        // update password and remove reset token
        account.PasswordHash = BCrypt.HashPassword(model.Password);
        account.PasswordReset = DateTime.UtcNow;
        account.ResetToken = "";
        account.ResetTokenExpires = null;

        _context.Accounts.Update(account);
        await _context.SaveChangesAsync();
    }

    public async Task<IEnumerable<AccountResponse>> GetAllAsync()
    {
        var accounts = await _context.Accounts.ToListAsync();
        return _mapper.Map<IList<AccountResponse>>(accounts);
    }

    public async Task<AccountResponse> GetByIdAsync(Guid id)
    {
        var account = await GetAccountAsync(id);
        return _mapper.Map<AccountResponse>(account);
    }

    public async Task<AccountResponse> CreateAsync(CreateRequest model)
    {
        // validate
        if (await _context.Accounts.AnyAsync(x => x.Email == model.Email))
            throw new UserExistException($"Email '{model.Email}' is already registered");

        // map model to new account object
        var account = _mapper.Map<Account>(model);
        account.Created = DateTime.UtcNow;
        account.Verified = DateTime.UtcNow;

        // hash password
        account.PasswordHash = BCrypt.HashPassword(model.Password);

        // save account
        await _context.Accounts.AddAsync(account);
        await _context.SaveChangesAsync();

        return _mapper.Map<AccountResponse>(account);
    }

    public async Task<AccountResponse> UpdateAsync(Guid id, UpdateRequest model)
    {
        var account = await GetAccountAsync(id);

        // validate
        if (account.Email != model.Email && await _context.Accounts.AnyAsync(x => x.Email == model.Email))
            throw new UserExistException($"Email '{model.Email}' is already registered");

        // hash password if it was entered
        if (!string.IsNullOrEmpty(model.Password))
            account.PasswordHash = BCrypt.HashPassword(model.Password);

        // copy model to account and save
        _mapper.Map(model, account);
        account.Updated = DateTime.UtcNow;
        _context.Accounts.Update(account);
        await _context.SaveChangesAsync();

        return _mapper.Map<AccountResponse>(account);
    }

    public async Task DeleteAsync(Guid id)
    {
        var account = await GetAccountAsync(id);
        _context.Accounts.Remove(account);
        _context.SaveChanges();
    }

    // helper methods
    private async Task<Account> GetAccountAsync(Guid id)
    {
        var account = await _context.Accounts.FindAsync(id);
        if (account == null)
        {
            throw new KeyNotFoundException("Account not found");
        }
        return account;
    }

    private void RemoveOldRefreshTokens(Account account)
    {
        account.RefreshTokens.RemoveAll(x =>
            !x.IsActive &&
            x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
    }

    private async Task<Account> GetAccountByRefreshTokenAsync(string token)
    {
        var account = await _context.Accounts
            .Include(x => x.RefreshTokens)
            .SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
        if (account == null)
        {
            throw new KeyNotFoundException("Invalid token");
        }
        return account;
    }

    private async Task<Account> GetAccountByResetTokenAsync(string token)
    {
        var account = await _context.Accounts.SingleOrDefaultAsync(x =>
            x.ResetToken == token && x.ResetTokenExpires > DateTime.UtcNow);
        if (account == null) throw new KeyNotFoundException("Invalid token");
        return account;
    }

    private void RevokeRefreshToken(RefreshToken token, string ipAddress, string reason = "", string replacedByToken = "")
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = reason;
        token.ReplacedByToken = replacedByToken;
    }

    private void RevokeDescendantRefreshTokens(RefreshToken refreshToken, Account account, string ipAddress, string reason)
    {
        // recursively traverse the refresh token chain and ensure all descendants are revoked
        if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
        {
            var childToken = account.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
            if (childToken.IsActive)
                RevokeRefreshToken(childToken, ipAddress, reason);
            else
                RevokeDescendantRefreshTokens(childToken, account, ipAddress, reason);
        }
    }

    private RefreshToken RotateRefreshToken(RefreshToken refreshToken, string ipAddress)
    {
        var newRefreshToken = _jwtUtils.GenerateRefreshToken(ipAddress);
        RevokeRefreshToken(refreshToken, ipAddress, "Replaced by new token", newRefreshToken.Token);
        return newRefreshToken;
    }

    private async Task SendAlreadyRegisteredEmailAsync(string email, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
            message = $@"<p>If you don't know your password please visit the <a href=""{origin}/account/forgot-password"">forgot password</a> page.</p>";
        else
            message = "<p>If you don't know your password you can reset it via the <code>/accounts/forgot-password</code> api route.</p>";

        await _emailService.SendEmailAsync(
            to: email,
            subject: "Sign-up Verification API - Email Already Registered",
            html: $@"<h4>Email Already Registered</h4>
                        <p>Your email <strong>{email}</strong> is already registered.</p>
                        {message}"
        );
    }

    private async Task SendPasswordResetEmailAsync(Account account, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
        {
            var resetUrl = $"{origin}/account/reset-password?token={account.ResetToken}";
            message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                            <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
        }
        else
        {
            message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                            <p><code>{account.ResetToken}</code></p>";
        }

        await _emailService.SendEmailAsync(
            to: account.Email,
            subject: "Sign-up Verification API - Reset Password",
            html: $@"<h4>Reset Password Email</h4>
                        {message}"
        );
    }

    private async Task SendVerificationEmailAsync(Account account, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
        {
            // origin exists if request sent from browser single page app (e.g. Angular or React)
            // so send link to verify via single page app
            var verifyUrl = $"{origin}/account/verify-email?token={account.VerificationToken}";
            message = $@"<p>Please click the below link to verify your email address:</p>
                            <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
        }
        else
        {
            // origin missing if request sent directly to api (e.g. from Postman)
            // so send instructions to verify directly with api
            message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            <p><code>{account.VerificationToken}</code></p>";
        }

        await _emailService.SendEmailAsync(
            to: account.Email,
            subject: "Sign-up Verification API - Verify Email",
            html: $@"<h4>Verify Email</h4>
                        <p>Thanks for registering!</p>
                        {message}"
        );
    }

    private async Task<string> GenerateVerificationTokenAsync()
    {
        // token is a cryptographically strong random sequence of values
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

        // ensure token is unique by checking against db
        var tokenIsUnique = !await _context.Accounts.AnyAsync(x => x.VerificationToken == token);
        if (!tokenIsUnique)
            return await GenerateVerificationTokenAsync();

        return token;
    }

    private async Task<string> GenerateResetTokenAsync()
    {
        // token is a cryptographically strong random sequence of values
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));

        // ensure token is unique by checking against db
        var tokenIsUnique = !await _context.Accounts.AnyAsync(x => x.ResetToken == token);
        if (!tokenIsUnique)
            return await GenerateResetTokenAsync();

        return token;
    }
}
