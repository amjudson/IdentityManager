using IdentityManger.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityManger.Authorize;
public class AdminWithOver1000DaysHandler(INumberOfDaysForAccount numberOfDaysForAccount)
	: AuthorizationHandler<AdminWithMore1000DaysRequirement>
{
	protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AdminWithMore1000DaysRequirement requirement)
	{
		if (!context.User.IsInRole(AppConstants.RoleAdmin))
		{
			return Task.CompletedTask;
		}

		var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
		var numberOfDays = numberOfDaysForAccount.Get(userId);
		if (numberOfDays >= requirement.Days)
		{
			context.Succeed(requirement);
		}

		return Task.CompletedTask;
	}
}
