using IdentityManger.Data;
using IdentityManger.Models;
using IdentityManger.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace IdentityManger.Controllers;

public class UserController(
	ApplicationDbContext db,
	UserManager<ApplicationUser> userManager,
	RoleManager<IdentityRole> roleManager) : Controller
{
	// GET: UserController
	public ActionResult Index()
	{
		var userList = db.ApplicationUsers.ToList();
		var userRoles = db.UserRoles.ToList();
		var roles = db.Roles.ToList();
		foreach (var user in userList)
		{
			var userRole = userRoles.FirstOrDefault(x => x.UserId == user.Id);
			if (userRole == null)
			{
				user.Role = "none";
			}
			else
			{
				user.Role = roles.FirstOrDefault(x => x.Id == userRole.RoleId).Name;
			}
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