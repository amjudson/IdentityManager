using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace IdentityManger.Data;
public class ApplicationDbContext(DbContextOptions options) : IdentityDbContext(options);
