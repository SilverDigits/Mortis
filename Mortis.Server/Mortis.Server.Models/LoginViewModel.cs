using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class LoginViewModel
	{
		[Required]
		[Display(Name = "Courrier électronique")]
		[EmailAddress]
		public string Email { get; set; }

		[Required]
		[DataType(DataType.Password)]
		[Display(Name = "Mot de passe")]
		public string Password { get; set; }

		[Display(Name = "Mémoriser mes informations")]
		public bool RememberMe { get; set; }
	}
}
