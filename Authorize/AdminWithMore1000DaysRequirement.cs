using Microsoft.AspNetCore.Authorization;

namespace IdentityManger.Authorize;
public class AdminWithMore1000DaysRequirement(int days) : IAuthorizationRequirement
{
	public int Days { get; set; } = days;
}
