using IdentityManger.Data;
using IdentityManger.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManger.Controllers;

public class UserController(ApplicationDbContext db, UserManager<ApplicationUser> userManager) : Controller
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
}