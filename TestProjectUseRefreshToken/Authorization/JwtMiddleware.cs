namespace TestProjectUseRefreshToken.Authorization;

using Microsoft.EntityFrameworkCore;
using TestProjectUseRefreshToken.Helpers;

public class JwtMiddleware
{
    private readonly RequestDelegate _next;

    public JwtMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context, DataContext dataContext, IJwtUtils jwtUtils)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        var accountId = jwtUtils.ValidateJwtToken(token);

        if (accountId != null)
        {
            // attach account to context on successful jwt validation
            context.Items["Account"] = await dataContext.Accounts
                .Include(x => x.RefreshTokens)
                .SingleOrDefaultAsync(x => x.Id == accountId);
        }

        await _next(context);
    }
}

