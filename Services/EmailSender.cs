using Microsoft.AspNetCore.Identity.UI.Services;
using SendGrid;
using SendGrid.Helpers.Mail;

namespace IdentityManger.Services;
public class EmailSender(IConfiguration config) : IEmailSender
{
	private readonly string sendGridKey = config["SendGrid:Key"] ?? throw new ArgumentNullException("SendGrid:Key");

	public Task SendEmailAsync(string email, string subject, string htmlMessage)
	{
		var apiKey = Environment.GetEnvironmentVariable("SENDGRID_API_KEY");
		var client = new SendGridClient(sendGridKey);
		var from_email = new EmailAddress("amjudson@reagan.com", "Mark Judson");
		var to_email = new EmailAddress(email);
		var msg = MailHelper.CreateSingleEmail(from_email, to_email, subject, "", htmlMessage);
		return client.SendEmailAsync(msg);
	}
}
