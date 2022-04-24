namespace TestProjectUseRefreshToken.Authorization;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using TestProjectUseRefreshToken.Entities;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class AuthorizeAttribute : Attribute, IAuthorizationFilter
{
    private readonly IList<Role> _roles;

    public AuthorizeAttribute(params Role[] roles)
    {
        _roles = roles;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        // authorization
        var account = context.HttpContext.Items["Account"] as Account;

        if (account == null)
        {
            // not logged in
            context.Result = new UnauthorizedResult();
        }
        else if (_roles.Any() && !_roles.Contains(account.Role))
        {
            //logged in and role not suitable
            context.Result = new ForbidResult();
        }
    }
}
