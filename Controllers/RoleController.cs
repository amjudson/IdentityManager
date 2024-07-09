using IdentityManger.Data;
using IdentityManger.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManger.Controllers;

public class RoleController(
	ApplicationDbContext db,
	UserManager<ApplicationUser> userManager,
	RoleManager<IdentityRole> roleManager) : Controller
{
	public ActionResult Index()
	{
		var roles = db.Roles.ToList();

		return View(roles);
	}

	[HttpGet]
	public IActionResult Upsert(string roleId)
	{
		if (string.IsNullOrEmpty(roleId))
		{
			return View();
		}
		else
		{
			var roleFromDb = db.Roles.FirstOrDefault(x => x.Id == roleId);
			return View(roleFromDb);
		}
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Upsert(IdentityRole roleObj)
	{
		if (await roleManager.RoleExistsAsync(roleObj.Name))
		{
			// error
		}

		if (string.IsNullOrEmpty(roleObj.NormalizedName))
		{
			await roleManager.CreateAsync(new IdentityRole {Name = roleObj.Name});
			TempData[AppConstants.NotificationSuccess] = "Role created successfully";
		}
		else
		{
			var roleFromDb = db.Roles.FirstOrDefault(x => x.Id == roleObj.Id);
			roleFromDb.Name = roleObj.Name;
			roleFromDb.NormalizedName = roleObj.Name.ToUpper();
			await roleManager.UpdateAsync(roleFromDb);
			TempData[AppConstants.NotificationSuccess] = "Role updated successfully";
		}

		return RedirectToAction(nameof(Index));
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Delete(string roleId)
	{
		var roleFromDb = db.Roles.FirstOrDefault(x => x.Id == roleId);
		if (roleFromDb != null)
		{
			var userRolesCount = db.UserRoles.Count(x => x.RoleId == roleId);
			if (userRolesCount > 0)
			{
				TempData[AppConstants.NotificationError] = "Role is assigned to some users. Please remove the role from users before deleting";
				return RedirectToAction(nameof(Index));
			}

			await roleManager.DeleteAsync(roleFromDb);
			TempData[AppConstants.NotificationSuccess] = "Role deleted successfully";
		}

		return RedirectToAction(nameof(Index));
	}
}