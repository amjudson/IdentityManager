﻿using System.ComponentModel.DataAnnotations;

namespace IdentityManger.Models.ViewModels;
public class ForgotPasswordViewModel
{
	[Required]
	[EmailAddress]
	public string Email { get; set; }
}
