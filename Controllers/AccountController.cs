using IdentityManger.Models;
using IdentityManger.Models.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;

namespace IdentityManger.Controllers;

[Authorize]
public class AccountController(
	UserManager<ApplicationUser> userManager,
	SignInManager<ApplicationUser> signInManager,
	IEmailSender emailSender,
	UrlEncoder urlEncoder) : Controller
{

	[AllowAnonymous]
	public IActionResult Register(string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		var registerViewModel = new RegisterViewModel();
		return View(registerViewModel);
	}

	[HttpPost]
	[AllowAnonymous]
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

	[AllowAnonymous]
	public IActionResult Login(string? returnUrl = null)
	{
		ViewData["ReturnUrl"] = returnUrl;
		return View();
	}

	[HttpPost]
	[AllowAnonymous]
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

			if (result.RequiresTwoFactor)
			{
				return RedirectToAction(nameof(VerifyAuthenticatorCode), new
				{
					model.RememberMe,
					returnUrl
				});
			}

			if (result.IsLockedOut)
			{
				return View("Lockout");
			}

			ModelState.AddModelError(string.Empty, "Invalid login attempt.");
		}

		return View(model);
	}

	[HttpGet]
	[AllowAnonymous]
	public async Task<IActionResult> VerifyAuthenticatorCode(bool rememberMe, string returnUrl = null)
	{
		var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
		if (user == null)
		{
			return View("Error");
		}

		ViewData["ReturnUrl"] = returnUrl;
		return View(new VerifyAuthenticatorViewModel
		{
			RememberMe = rememberMe,
			ReturnUrl = returnUrl,
		});
	}

	[HttpPost]
	[AllowAnonymous]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> VerifyAuthenticatorCode(VerifyAuthenticatorViewModel model)
	{
		model.ReturnUrl ??= Url.Content("~/");
		if (!ModelState.IsValid)
		{
			return View(model);
		}

		var result = await signInManager.TwoFactorAuthenticatorSignInAsync(
			model.Code,
			model.RememberMe,
			rememberClient: false);
		if (result.Succeeded)
		{
			return LocalRedirect(model.ReturnUrl);
		}

		if (result.IsLockedOut)
		{
			return View("Lockout");
		}

		ModelState.AddModelError(string.Empty, "Invalid login attempt.");
		return View(model);
	}

	[HttpGet]
	public async Task<IActionResult> RemoveAuthenticator()
	{
		var user = await userManager.GetUserAsync(User);
		if (user == null)
		{
			return NotFound();
		}

		await userManager.ResetAuthenticatorKeyAsync(user);
		await userManager.SetTwoFactorEnabledAsync(user, false);

		return RedirectToAction(nameof(Index), "Home");
	}

	[HttpPost]
	[AllowAnonymous]
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
	[AllowAnonymous]
	public IActionResult Lockout()
	{
		return View();
	}

	[HttpGet]
	[AllowAnonymous]
	public IActionResult ForgotPassword()
	{
		return View();
	}

	[HttpPost]
	[ValidateAntiForgeryToken]
	[AllowAnonymous]
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
	[AllowAnonymous]
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
	[AllowAnonymous]
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
	[AllowAnonymous]
	public IActionResult ResetPasswordConfirmation()
	{
		return View();
	}

	[HttpGet]
	[AllowAnonymous]
	public IActionResult AuthenticatorConfirmation()
	{
		return View();
	}

	[HttpGet]
	[Authorize]
	public async Task<IActionResult> EnableAuthenticator()
	{
		var authenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
		var user = await userManager.GetUserAsync(User);
		if (user == null)
		{
			return NotFound();
		}

		await userManager.ResetAuthenticatorKeyAsync(user);
		var token = await userManager.GetAuthenticatorKeyAsync(user);

		var authUri = string.Format(
			authenticatorUriFormat,
			urlEncoder.Encode("IdentityManger"),
			urlEncoder.Encode(user.Email),
			token);
		var model = new TwoFactorAuthenticationViewModel
		{
			Token = token,
			QRCodeUrl = authUri,
		};
		return View(model);
	}

	[HttpPost]
	[Authorize]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> EnableAuthenticator(TwoFactorAuthenticationViewModel model)
	{
		if (ModelState.IsValid)
		{
			var user = await userManager.GetUserAsync(User);
			var succeded = await userManager.VerifyTwoFactorTokenAsync(
				user,
				userManager.Options.Tokens.AuthenticatorTokenProvider,
				model.Code);
			if (succeded)
			{
				await userManager.SetTwoFactorEnabledAsync(user, true);
			}
			else
			{
				ModelState.AddModelError("Verify", "Your two factor auth code could not be validated.");
				return View(model);
			}

			return RedirectToAction(nameof(AuthenticatorConfirmation));
		}

		return View("Error");
	}

	private void AddErrors(IdentityResult result)
	{
		foreach (var error in result.Errors)
		{
			ModelState.AddModelError(string.Empty, error.Description);
		}
	}
}