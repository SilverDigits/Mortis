using System.ComponentModel.DataAnnotations;

namespace Mortis.Server.Models
{
	public class ResetPasswordViewModel
	{
		[Required]
		[EmailAddress]
		[Display(Name = "Courrier électronique")]
		public string Email { get; set; }

		[Required]
		[StringLength(100, ErrorMessage = "{0} doit contenir au moins {2} caractères.", MinimumLength = 6)]
		[DataType(DataType.Password)]
		[Display(Name = "Mot de passe")]
		public string Password { get; set; }

		[DataType(DataType.Password)]
		[Display(Name = "Confirmer le mot de passe")]
		[Compare("Password", ErrorMessage = "Le nouveau mot de passe et le mot de passe de confirmation ne correspondent pas.")]
		public string ConfirmPassword { get; set; }

		public string Code { get; set; }
	}
}
