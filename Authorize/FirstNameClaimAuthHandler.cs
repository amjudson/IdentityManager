using IdentityManger.Data;
using IdentityManger.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityManger.Authorize;
public class FirstNameClaimAuthHandler(
	UserManager<ApplicationUser> userManager,
	ApplicationDbContext db
	) : AuthorizationHandler<FirstNameClaimAuthRequirement>
{
	protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameClaimAuthRequirement requirement)
	{
		var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
		var user = db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
		if (user != null)
		{
			var firstNameClaim = userManager.GetClaimsAsync(user)
				.GetAwaiter().GetResult()
				.FirstOrDefault(u => u.Type == "FirstName");

			if (firstNameClaim != null)
			{
				if (firstNameClaim.Value.ToLower().Contains(requirement.FirstName.ToLower()))
				{
					context.Succeed(requirement);
				}
			}
		}

		return Task.CompletedTask;
	}
}
