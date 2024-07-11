using IdentityManger.Data;
using IdentityManger.Services.IServices;

namespace IdentityManger.Services;
public class NumberOfDaysForAccount(ApplicationDbContext db) : INumberOfDaysForAccount
{
	public int Get(string userId)
	{
		var user = db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
		if (user != null && user.DateCreated != DateTime.MinValue)
		{
			return (DateTime.Now - user.DateCreated).Days;
		}

		return 0;
	}
}
