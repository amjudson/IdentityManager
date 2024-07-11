using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManger.Controllers;

[Authorize]
public class AccessCheckerController : Controller
{
	// Anyone can access this
	[AllowAnonymous]
	public ActionResult AllAccess()
	{
		return View();
	}

	// Only authorized users can access this (logged in)
	public ActionResult AuthorizedAccess()
	{
		return View();
	}

	// Only users in the User or Admin role can access this
	[Authorize(Roles = $"{AppConstants.RoleUser},{AppConstants.RoleAdmin}")]
	public ActionResult UserOrAdminRoleAccess()
	{
		return View();
	}

	// Only users in the User or Admin role can access this
	[Authorize(Policy = "AdminAndUser")]
	public ActionResult UserAndAdminRoleAccess()
	{
		return View();
	}

	// Only users in the Admin role can access this
	[Authorize(Policy = AppConstants.RoleAdmin)]
	public ActionResult AdminRoleAccess()
	{
		return View();
	}

	// Only users with the Admin and Create Claim can access this
	[Authorize(Policy = "Admin_CreateClaim")]
	public ActionResult AdminCreateAccess()
	{
		return View();
	}

	// Only users with the Admin and (Create & Edit & Delete) Claim can access this
	[Authorize(Policy = "Admin_CreateEditDeleteClaim")]
	public ActionResult AdminCreateEditDeleteAccess()
	{
		return View();
	}

	// Only users with the Admin and (Create & Edit & Delete) Claim can access this
	[Authorize(Policy = "Admin_CreateEditDeleteClaim_ORSuperAdmin")]
	public ActionResult AdminCreateEditDeleteOrSuperAdminAccess()
	{
		return View();
	}

	[Authorize(Policy = "AdminWithMore1000Days")]
	public IActionResult OnlyAdmin1000()
	{
		return View();
	}

	[Authorize(Policy = "FirstNameAuth")]
	public IActionResult FirstNameAuth()
	{
		return View();
	}
}