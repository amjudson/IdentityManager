using IdentityManger;
using IdentityManger.Authorize;
using IdentityManger.Data;
using IdentityManger.Models;
using IdentityManger.Services;
using IdentityManger.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<ApplicationDbContext>(options =>
	options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
	.AddEntityFrameworkStores<ApplicationDbContext>()
	.AddDefaultTokenProviders();

builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddScoped<INumberOfDaysForAccount, NumberOfDaysForAccount>();
builder.Services.AddScoped<IAuthorizationHandler, AdminWithOver1000DaysHandler>();
builder.Services.AddScoped<IAuthorizationHandler, FirstNameClaimAuthHandler>();

builder.Services.ConfigureApplicationCookie(o =>
{
	o.AccessDeniedPath = "/Account/NoAccess";
});

builder.Services.Configure<IdentityOptions>(o =>
{
	o.Password.RequireDigit = false;
	o.Password.RequireLowercase = false;
	o.Password.RequireUppercase = false;
	o.Password.RequireNonAlphanumeric = false;
	o.Password.RequiredLength = 6;
	o.Lockout.MaxFailedAccessAttempts = 3;
	o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
	o.SignIn.RequireConfirmedEmail = false;
});

builder.Services.AddAuthorization(options =>
{
	options.AddPolicy(AppConstants.RoleAdmin, policy => { policy.RequireRole(AppConstants.RoleAdmin); });
	options.AddPolicy("AdminAndUser", policy =>
	{
		policy.RequireRole(AppConstants.RoleAdmin)
			.RequireRole(AppConstants.RoleUser);
	});
	options.AddPolicy("Admin_CreateClaim", policy =>
	{
		policy.RequireRole(AppConstants.RoleAdmin);
		policy.RequireClaim(AppConstants.ClaimCreate, "True");
	});
	options.AddPolicy("Admin_CreateEditDeleteClaim", policy =>
	{
		policy.RequireRole(AppConstants.RoleAdmin)
			.RequireClaim(AppConstants.ClaimCreate, "True")
			.RequireClaim(AppConstants.ClaimEdit, "True")
			.RequireClaim(AppConstants.ClaimDelete, "True");
	});
	options.AddPolicy("Admin_CreateEditDeleteClaim_ORSuperAdmin", policy =>
	{
		policy.RequireAssertion(context => (
			                                   context.User.IsInRole(AppConstants.RoleAdmin)
			                                   && context.User.HasClaim(AppConstants.ClaimCreate, "True")
			                                   && context.User.HasClaim(AppConstants.ClaimEdit, "True")
			                                   && context.User.HasClaim(AppConstants.ClaimDelete, "True"))
		                                   || context.User.IsInRole(AppConstants.RoleSuperAdmin));
	});
	options.AddPolicy("OnlySuperAdminChecker", policy =>
	{
		policy.Requirements.Add(new OnlySuperAdminChecker());
	});
	options.AddPolicy("AdminWithMore1000Days", policy =>
	{
		policy.Requirements.Add(new AdminWithMore1000DaysRequirement(1000));
	});
	options.AddPolicy("FirstNameAuth", policy =>
	{
		policy.Requirements.Add(new FirstNameClaimAuthRequirement("admin"));
	});
});

builder.Services.AddAuthentication().AddMicrosoftAccount(opt =>
{
	opt.ClientId = builder.Configuration["SSOAuthentication:MS_ClientId"] ?? "ClientId";
	opt.ClientSecret = builder.Configuration["SSOAuthentication:MS_ClientSecret"] ?? "ClientSecret";
});

builder.Services.AddAuthentication().AddFacebook(opt =>
{
	opt.ClientId = builder.Configuration["SSOAuthentication:FB_ClientId"] ?? "ClientId";
	opt.ClientSecret = builder.Configuration["SSOAuthentication:FB_ClientSecret"] ?? "ClientSecret";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
	app.UseExceptionHandler("/Home/Error");
	// The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
	app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
	name: "default",
	pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();