using Microsoft.AspNetCore.Authorization;

namespace IdentityManger.Authorize;
public class OnlySuperAdminChecker : AuthorizationHandler<OnlySuperAdminChecker>, IAuthorizationRequirement
{
	protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySuperAdminChecker requirement)
	{
		if (context.User.IsInRole(AppConstants.RoleSuperAdmin))
		{
			context.Succeed(requirement);
			return Task.CompletedTask;
		}

		return Task.CompletedTask;
	}
}
