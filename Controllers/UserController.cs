using IdentityManger.Data;
using IdentityManger.Models;
using IdentityManger.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace IdentityManger.Controllers;

public class UserController(
	ApplicationDbContext db,
	UserManager<ApplicationUser> userManager,
	RoleManager<IdentityRole> roleManager) : Controller
{
	// GET: UserController
	public async Task<ActionResult> Index()
	{
		var userList = db.ApplicationUsers.ToList();
		var userRoles = db.UserRoles.ToList();
		var roles = db.Roles.ToList();
		foreach (var user in userList)
		{
			var userRole = await userManager.GetRolesAsync(user);
			user.Roles = string.Join(",", userRole);
			var claims = userManager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(c => c.Type);
			user.UserClaims = string.Join(",", claims);

		}

		return View(userList);
	}

	public async Task<IActionResult> ManageRole(string userId)
	{
		var user = await userManager.FindByIdAsync(userId);
		if (user == null)
		{
			return NotFound();
		}

		var existingUserRoles = await userManager.GetRolesAsync(user) as List<string>;
		var model = new RolesViewModel
		{
			User = user,
		};

		foreach (var role in roleManager.Roles)
		{
			var roleSelection = new RoleSelection
			{
				RoleName = role.Name,
				IsSelected = existingUserRoles.Any(r => r == role.Name),
			};

			model.RolesList.Add(roleSelection);
		}

		return View(model);
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
	{
		var user = await userManager.FindByIdAsync(rolesViewModel.User.Id);
		if (user == null)
		{
			return NotFound();
		}

		var oldUserRoles = await userManager.GetRolesAsync(user);
		var result = await userManager.RemoveFromRolesAsync(user, oldUserRoles);
		if (!result.Succeeded)
		{
			TempData[AppConstants.NotificationError] = $"Failed to remove existing roles for user '{user.Name}'";
			return View(rolesViewModel);
		}

		result = await userManager.AddToRolesAsync(
			user,
			rolesViewModel.RolesList.Where(x => x.IsSelected).Select(x => x.RoleName));

		if (!result.Succeeded)
		{
			TempData[AppConstants.NotificationError] = $"Error adding roles to user '{user.Name}'";
			return View(rolesViewModel);
		}

		TempData[AppConstants.NotificationSuccess] = $"Roles assigned successfully to user '{user.Name}'";
		return RedirectToAction(nameof(Index));
	}

	public async Task<IActionResult> ManageUserClaim(string userId)
	{
		var user = await userManager.FindByIdAsync(userId);
		if (user == null)
		{
			return NotFound();
		}

		var existingUserClaims = await userManager.GetClaimsAsync(user);
		var model = new ClaimsViewModel
		{
			User = user,
		};

		foreach (var claim in ClaimStore.ClaimsList)
		{
			var claimSelection = new ClaimSelection
			{
				ClaimType = claim.Type,
				IsSelected = existingUserClaims.Any(r => r.Type == claim.Type),
			};

			model.ClaimsList.Add(claimSelection);
		}

		return View(model);
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
	{
		var user = await userManager.FindByIdAsync(claimsViewModel.User.Id);
		if (user == null)
		{
			return NotFound();
		}

		var oldUserClaims = await userManager.GetClaimsAsync(user);
		var result = await userManager.RemoveClaimsAsync(user, oldUserClaims);
		if (!result.Succeeded)
		{
			TempData[AppConstants.NotificationError] = $"Failed to remove existing claims for user '{user.Name}'";
			return View(claimsViewModel);
		}

		result = await userManager.AddClaimsAsync(
			user,
			claimsViewModel.ClaimsList
				.Where(x => x.IsSelected)
				.Select(x => new Claim(x.ClaimType, x.IsSelected.ToString())));

		if (!result.Succeeded)
		{
			TempData[AppConstants.NotificationError] = $"Error adding claims to user '{user.Name}'";
			return View(claimsViewModel);
		}

		TempData[AppConstants.NotificationSuccess] = $"Claims assigned successfully to user '{user.Name}'";
		return RedirectToAction(nameof(Index));
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> LockUnlock(string userId)
	{
		var user = await db.ApplicationUsers.FirstOrDefaultAsync(u => u.Id == userId);
		if (user == null)
		{
			return NotFound();
		}

		if (user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
		{
			user.LockoutEnd = DateTime.Now;
			TempData[AppConstants.NotificationSuccess] = $"User '{user.Name}' unlocked successfully";
		}
		else
		{
			user.LockoutEnd = DateTime.Now.AddYears(100);
			TempData[AppConstants.NotificationSuccess] = $"User '{user.Name}' locked successfully";
		}

		await db.SaveChangesAsync();
		return RedirectToAction(nameof(Index));
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> DeleteUser(string userId)
	{
		var user = await db.ApplicationUsers.FirstOrDefaultAsync(u => u.Id == userId);
		if (user == null)
		{
			return NotFound();
		}

		db.ApplicationUsers.Remove(user);
		await db.SaveChangesAsync();
		TempData[AppConstants.NotificationSuccess] = $"User '{user.Name}' deleted successfully";
		return RedirectToAction(nameof(Index));
	}
}