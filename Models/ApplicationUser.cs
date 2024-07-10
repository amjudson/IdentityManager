using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityManger.Models;
public class ApplicationUser : IdentityUser
{
	[Required]
	public string Name { get; set; }

	[NotMapped]
	public string RoleId { get; set; }

	[NotMapped]
	public string Roles { get; set; }
	[NotMapped]
	public string UserClaims { get; set; }
}
