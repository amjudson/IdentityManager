using IdentityManger.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManger.Data;
public class ApplicationDbContext(DbContextOptions options) : IdentityDbContext(options)
{
	public DbSet<ApplicationUser> ApplicationUsers { get; set; }
}

