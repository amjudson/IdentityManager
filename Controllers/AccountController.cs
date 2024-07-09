using IdentityManger.Models;
using IdentityManger.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManger.Controllers;

public class AccountController(
	UserManager<ApplicationUser> userManager,
	SignInManager<ApplicationUser> signInManager,
	IEmailSender emailSender) : Controller
{
	public IActionResult Register(string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		var registerViewModel = new RegisterViewModel();
		return View(registerViewModel);
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Register(RegisterViewModel model, string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		returnUrl ??= Url.Content("~/");
		if (ModelState.IsValid)
		{
			var user = new ApplicationUser
			{
				UserName = model.Email,
				Email = model.Email,
				Name = model.Name,
			};

			var result = await userManager.CreateAsync(user, model.Password);
			if (result.Succeeded)
			{

				var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
				var callbackUrl = Url.Action("ConfirmEmail", "Account", new
				{
					userid = user.Id,
					code
				}, protocol: HttpContext.Request.Scheme);
				await emailSender.SendEmailAsync(model.Email, "Confirm Email - Identity Manger",
					$"Please confirm your email by clicking here: <a href='{callbackUrl}'>link</a>");

				await signInManager.SignInAsync(user, isPersistent: false);
				return LocalRedirect(returnUrl);
			}

			AddErrors(result);
		}

		return View(model);
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> LogOff()
	{
		await signInManager.SignOutAsync();
		return RedirectToAction("Index", "Home");
	}

	public IActionResult Login(string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		return View();
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		returnUrl ??= Url.Content("~/");
		if (ModelState.IsValid)
		{
			var result = await signInManager.PasswordSignInAsync(
				model.Email,
				model.Password,
				model.RememberMe,
				lockoutOnFailure: true);
			if (result.Succeeded)
			{
				return LocalRedirect(returnUrl);
			}

			if (result.IsLockedOut)
			{
				return View("Lockout");
			}

			ModelState.AddModelError(string.Empty, "Invalid login attempt.");
		}

		return View(model);
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> ConfirmEmail(string code, string userId)
	{
		if (ModelState.IsValid)
		{
			var user = await userManager.FindByIdAsync(userId);
			if (user == null)
			{
				return View("Error");
			}

			var result = await userManager.ConfirmEmailAsync(user, code);
			if (result.Succeeded)
			{
				return View();
			}
		}

		return View("Error");
	}

	[HttpGet]
	public IActionResult Lockout()
	{
		return View();
	}

	[HttpGet]
	public IActionResult ForgotPassword()
	{
		return View();
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
	{
		if (ModelState.IsValid)
		{
			var user = await userManager.FindByEmailAsync(model.Email);
			if (user == null)
			{
				return RedirectToAction("ForgotPasswordConfirmation");
			}

			var code = await userManager.GeneratePasswordResetTokenAsync(user);
			var callbackUrl = Url.Action("ResetPassword", "Account", new
			{
				userid = user.Id,
				code
			}, protocol: HttpContext.Request.Scheme);

			await emailSender.SendEmailAsync(model.Email, "Reset Password - Identity Manger",
				$"Please reset your password by clicking here: <a href='{callbackUrl}'>link</a>");
			return RedirectToAction(nameof(ForgotPasswordConfirmation));
		}

		return View(model);
	}

	[HttpGet]
	public IActionResult ForgotPasswordConfirmation()
	{
		return View();
	}

	[HttpGet]
	public IActionResult ResetPassword(string code = null)
	{
		return code == null ? View("Error") : View();
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
	{
		if (ModelState.IsValid)
		{
			var user = await userManager.FindByEmailAsync(model.Email);
			if (user == null)
			{
				return RedirectToAction(nameof(ResetPasswordConfirmation));
			}

			var result = await userManager.ResetPasswordAsync(user, model.Code, model.Password);
			if (result.Succeeded)
			{
				return RedirectToAction(nameof(ResetPasswordConfirmation));
			}

			AddErrors(result);
		}

		return View(model);
	}

	[HttpGet]
	public IActionResult ResetPasswordConfirmation()
	{
		return View();
	}

	private void AddErrors(IdentityResult result)
	{
		foreach (var error in result.Errors)
		{
			ModelState.AddModelError(string.Empty, error.Description);
		}
	}
}