using Microsoft.AspNetCore.Authorization;

namespace IdentityManger.Authorize;
public class FirstNameClaimAuthRequirement(string firstName) : IAuthorizationRequirement
{
	public string FirstName { get; set; } = firstName;
}
