namespace IdentityManger.Models.ViewModels;
public class ClaimsViewModel
{
	public ClaimsViewModel()
	{
		ClaimsList = [];
	}

	public ApplicationUser User { get; set; }
	public List<ClaimSelection> ClaimsList { get; set; }
}

public class ClaimSelection
{
	public string ClaimType { get; set; }
	public bool IsSelected { get; set; }
}
